import boto3
import pandas as pd
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import json

#获取AWS资源数量统计
def get_aws_resource_counts():
    resource_counts = defaultdict(int)
    try:
        clients = {
            'ec2': ('EC2 实例', 'describe_instances', lambda x: sum(len(r['Instances']) for r in x['Reservations'])),
            's3': ('S3 存储桶', 'list_buckets', lambda x: len(x['Buckets'])),
            'rds': ('RDS 数据库', 'describe_db_instances', lambda x: len(x['DBInstances'])),
            'lambda': ('Lambda 函数', 'list_functions', lambda x: len(x['Functions'])),
            'ecs': ('ECS 集群', 'list_clusters', lambda x: len(x['clusterArns'])),
            'elasticache': ('ElastiCache 集群', 'describe_cache_clusters', lambda x: len(x['CacheClusters'])),
            'kms': ('KMS 密钥', 'list_keys', lambda x: len(x['Keys'])),
        }
        
        for service, (name, method, counter) in clients.items():
            try:
                client = boto3.client(service)
                response = getattr(client, method)()
                resource_counts[name] = counter(response)
            except Exception as e:
                print(f"获取{name}数量时发生错误: {str(e)}")
        
        # 获取EC2卷数量
        try:
            ec2 = boto3.client('ec2')
            volumes = ec2.describe_volumes()
            resource_counts['EBS 卷'] = len(volumes['Volumes'])
        except Exception as e:
            print(f"获取EBS卷数量时发生错误: {str(e)}")
        
        # 获取VPC相关资源数量
        try:
            vpc_response = ec2.describe_vpcs()
            resource_counts['VPC'] = len(vpc_response['Vpcs'])
        except Exception as e:
            print(f"获取VPC相关资源数量时发生错误: {str(e)}")
                
    except Exception as e:
        print(f"获取资源数量时发生错误: {str(e)}")
        return None
    return resource_counts

#解析CloudWatch告警的比较运算符
def parse_operator(operator):
    operator_map = {
        'GreaterThanOrEqualToThreshold': '>=',
        'GreaterThanThreshold': '>',
        'LessThanOrEqualToThreshold': '<=',
        'LessThanThreshold': '<',
        'GreaterThanUpperThreshold': '>',
        'LessThanLowerThreshold': '<',
        'EqualToThreshold': '='
    }
    return operator_map.get(operator, operator)

# 获取CloudWatch告警
def get_alarm_details():
    alarm_detail = []

    try:
        cloudwatch = boto3.client('cloudwatch')
            
        # 获取所有告警（处理分页）
        all_alarms = []
        paginator = cloudwatch.get_paginator('describe_alarms')
            
        # 遍历所有页面
        for page in paginator.paginate():
            # 合并指标告警和复合告警
            if 'MetricAlarms' in page:
                all_alarms.extend(page['MetricAlarms'])
            if 'CompositeAlarms' in page:
                all_alarms.extend(page['CompositeAlarms'])

        for alarm in all_alarms:
            # 基础信息
            details = {
                '名称': alarm.get('AlarmName', '未知'),
                '描述': alarm.get('AlarmDescription', '无描述'),
                '状态': alarm.get('StateValue', '未知'),
                '类型': '复合告警' if 'AlarmRule' in alarm else '指标告警',
                '指标名称': '未知',
                '命名空间': '未知',
                '阈值': '未知',
                '评估周期': '未知',
                '历史记录': []  # 新增历史记录字段
            }

            # 获取告警历史记录
            try:
                history_paginator = cloudwatch.get_paginator('describe_alarm_history')
                history_pages = history_paginator.paginate(
                    AlarmName=alarm.get('AlarmName'),
                    HistoryItemType='StateUpdate'
                )
                
                for history_page in history_pages:
                    for history_item in history_page['AlarmHistoryItems']:
                        history_data = json.loads(history_item.get('HistoryData', '{}'))
                        if 'newState' in history_data:
                            state_data = history_data['newState'].get('stateReasonData', {})
                            if 'evaluatedDatapoints' in state_data:
                                for datapoint in state_data['evaluatedDatapoints']:
                                    history_record = {
                                        '时间': datapoint.get('timestamp', '未知'),
                                        '状态': history_item.get('HistorySummary', '未知'),
                                        '详细信息': f"value: {datapoint.get('value', '未知')}"
                                    }
                                    details['历史记录'].append(history_record)
            except Exception as e:
                print(f"获取告警 {alarm.get('AlarmName')} 的历史记录时发生错误: {str(e)}")

            # 处理多指标告警
            if 'Metrics' in alarm:  
                for metric in alarm['Metrics']:
                    if 'MetricStat' in metric:
                        metric_stat = metric['MetricStat']
                        metric_name = metric_stat['Metric'].get('MetricName', '未知')
                        details['指标名称'] = metric_name
                        details['命名空间'] = metric_stat['Metric'].get('Namespace', '未知')
                        period = metric_stat.get('Period', '未知')
                        details['评估周期'] = f"{int(period/60) if isinstance(period, (int, float)) else period} 分钟"
                        details['类型'] = '多指标告警'
                    
                    # 处理数学表达式指标
                    if 'Expression' in metric:
                        details['阈值'] = metric.get('Expression', '未知')
                        break
                    
                # 如果没有找到表达式，尝试使用普通阈值
                if details['阈值'] == '未知':
                    threshold = alarm.get('Threshold', '未知')
                    operator = alarm.get('ComparisonOperator', '')
                    if threshold != '未知' and operator:
                        details['阈值'] = f"{details['指标名称']} {parse_operator(operator)} {threshold}"
                    
            # 处理单指标告警
            elif 'MetricName' in alarm:  
                metric_name = alarm.get('MetricName')
                period = alarm.get('Period', '未知')
                period_str = f"{int(period/60) if isinstance(period, (int, float)) else period} 分钟"
                
                details.update({
                    '指标名称': metric_name,
                    '命名空间': alarm.get('Namespace', '未知'),
                    '阈值': f"{metric_name}{parse_operator(alarm.get('ComparisonOperator', ''))}{alarm.get('Threshold', '未知')} ",
                    '评估周期': period_str
                })

            # 对于复合告警，添加规则信息
            elif 'AlarmRule' in alarm:
                details.update({
                    '指标名称': '复合告警',
                    '命名空间': '复合告警',
                    '阈值': alarm.get('AlarmRule', '不适用'),
                    '评估周期': '不适用'
                })

            # 确保所有值都是字符串类型并处理特殊字符
            for key in details:
                if key != '历史记录':  # 跳过历史记录数组
                    if not isinstance(details[key], str):
                        details[key] = str(details[key])
                    # 处理可能包含的特殊字符，避免破坏Markdown表格格式
                    details[key] = details[key].replace('|', '\\|').replace('\n', ' ')
                
            alarm_detail.append(details)
    except Exception as e:
        print(f"获取告警信息时发生错误: {str(e)}")
        return None
    return alarm_detail


#获取安全组信息
def get_security_group_details():
    security_groups = []
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_security_groups()
        
        for group in response['SecurityGroups']:
            sg_info = {
                '名称': group['GroupName'],
                '安全组ID': group['GroupId'],
                'VPC ID': group.get('VpcId', '默认VPC'),
                '描述': group.get('Description', '无描述'),
                '入站规则': [],
                '出站规则': []
            }
            
            # 处理入站规则
            for rule in group.get('IpPermissions', []):
                rule_info = _format_security_rule(rule)
                sg_info['入站规则'].append(rule_info)
            
            # 处理出站规则
            for rule in group.get('IpPermissionsEgress', []):
                rule_info = _format_security_rule(rule)
                sg_info['出站规则'].append(rule_info)
            
            security_groups.append(sg_info)
            
    except Exception as e:
        print(f"获取安全组信息时发生错误: {str(e)}")
        return None
    return security_groups

def _format_security_rule(rule):
    """格式化安全组规则"""
    protocol = rule.get('IpProtocol', '-1')
    if protocol == '-1':
        protocol = '所有'
    elif protocol == '-2':
        protocol = 'ICMP'
        
    from_port = rule.get('FromPort', '')
    to_port = rule.get('ToPort', '')
    port_range = ''
    if from_port == to_port and from_port is not None:
        port_range = str(from_port)
    elif from_port is not None and to_port is not None:
        port_range = f"{from_port}-{to_port}"
    
    sources = []
    for ip_range in rule.get('IpRanges', []):
        cidr = ip_range.get('CidrIp', '')
        description = ip_range.get('Description', '')
        sources.append(f"{cidr} ({description})" if description else cidr)
    
    return {
        '协议': protocol,
        '端口范围': port_range,
        '源/目标': '\t'.join(sources) if sources else ['无']  # 返回源/目标地址列表
    }



#处理WAF Web ACL的详细信息
def get_waf_details():
    waf_info = []
    try:
        wafv2 = boto3.client('wafv2', region_name='cn-north-1')
        
        # 获取所有Web ACL
        for scope in ['REGIONAL']:  # 只获取区域级别的WAF
            response = wafv2.list_web_acls(Scope=scope)
            for web_acl in response.get('WebACLs', []):
                acl_info = {
                    '名称': web_acl.get('Name', '未知'),
                    'ACL ID': web_acl.get('Id', '未知'),
                    'ARN': web_acl.get('ARN', '未知'),
                    '关联资源': []
                }
                
                # 获取关联的资源
                try:
                    resources = wafv2.list_resources_for_web_acl(
                        WebACLArn=web_acl['ARN']
                    )
                    for arn in resources.get('ResourceArns', []):
                        resource_type = '未知'
                        if 'cloudfront' in arn:
                            resource_type = 'CloudFront'
                        elif 'apigateway' in arn:
                            resource_type = 'API Gateway'
                        elif 'elasticloadbalancing' in arn:
                            resource_type = 'ALB'
                        acl_info['关联资源'].append({
                            '类型': resource_type,
                            'ARN': arn
                        })
                except Exception as e:
                    print(f"获取WAF关联资源时发生错误: {str(e)}")
                
                waf_info.append(acl_info)
                
    except Exception as e:
        print(f"获取WAF信息时发生错误: {str(e)}")
        return None
    return waf_info

#过滤安全建议
def filter_findings_by_severity(findings, severity_levels=None):
    if not severity_levels:
        return findings
    
    severity_levels = [level.upper() for level in severity_levels]
    return [finding for finding in findings if finding['严重程度'].upper() in severity_levels]


#处理Security Hub的安全建议
def get_security_findings(severity_levels=None):
    findings = []
    try:
        # 获取SecurityHub的发现
        try:
            securityhub = boto3.client('securityhub', region_name='cn-north-1')
            paginator = securityhub.get_paginator('get_findings')
            for page in paginator.paginate(
                Filters={
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                }
            ):
                for finding in page.get('Findings', []):
                    severity = finding.get('Severity', {}).get('Label', '未知')
                    findings.append({
                        '来源': 'Security Hub',
                        '严重程度': severity,
                        '标题': finding.get('Title', '未知'),
                        '描述': finding.get('Description', '无描述'),
                        '资源类型': finding.get('Resources', [{}])[0].get('Type', '未知'),
                        '资源ID': finding.get('Resources', [{}])[0].get('Id', '未知'),
                        '建议': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', '无建议'),
                        '发现时间': finding.get('CreatedAt', '未知')
                    })
        except Exception as e:
            print(f"获取SecurityHub数据时发生错误: {str(e)}")

        # 获取GuardDuty的发现
        try:
            guardduty = boto3.client('guardduty', region_name='cn-north-1')
            detectors = guardduty.list_detectors()
            
            for detector_id in detectors.get('DetectorIds', []):
                # 获取所有活跃的安全发现ID
                finding_ids = []
                paginator = guardduty.get_paginator('list_findings')
                for page in paginator.paginate(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'service.archived': {
                                'Eq': ['false']
                            }
                        }
                    }
                ):
                    finding_ids.extend(page.get('FindingIds', []))
                
                # 分批获取发现的详细信息
                batch_size = 50
                for i in range(0, len(finding_ids), batch_size):
                    batch_ids = finding_ids[i:i + batch_size]
                    try:
                        findings_response = guardduty.get_findings(
                            DetectorId=detector_id,
                            FindingIds=batch_ids
                        )
                        
                        for finding in findings_response.get('Findings', []):
                            # 将GuardDuty的数字严重程度转换为文本
                            severity_num = finding.get('Severity', 0)
                            if severity_num >= 7:
                                severity = 'HIGH'
                            elif severity_num >= 4:
                                severity = 'MEDIUM'
                            else:
                                severity = 'LOW'
                            
                            findings.append({
                                '来源': 'GuardDuty',
                                '严重程度': severity,
                                '标题': finding.get('Title', '未知'),
                                '描述': finding.get('Description', '无描述'),
                                '资源类型': finding.get('Resource', {}).get('ResourceType', '未知'),
                                '资源ID': finding.get('Resource', {}).get('ResourceId', '未知'),
                                '建议': '\n'.join([
                                    f"- {action.get('Description', '')}"
                                    for action in finding.get('Service', {}).get('Action', {}).get('RecommendedActions', [])
                                ]) or finding.get('Service', {}).get('Action', {}).get('Recommendation', {}).get('Text', '无建议'),
                                '发现时间': finding.get('CreatedAt', '未知')
                            })
                    except Exception as e:
                        print(f"获取GuardDuty发现详情时出错 (批次 {i//batch_size + 1}): {str(e)}")
                        continue
                        
        except Exception as e:
            print(f"获取GuardDuty数据时发生错误: {str(e)}")
                
    except Exception as e:
        print(f"获取安全建议时发生错误: {str(e)}")
        return None
    return filter_findings_by_severity(findings, severity_levels)

#获取生命周期管理器策略信息
def get_dlm_policy_details():
    try:
        dlm = boto3.client('dlm')
        policies = []
        
        # 直接获取所有生命周期策略
        response = dlm.get_lifecycle_policies()
        
        for policy_summary in response.get('Policies', []):
            try:
                policy_id = policy_summary.get('PolicyId')
                policy = dlm.get_lifecycle_policy(PolicyId=policy_id)
                
                if 'Policy' in policy:
                    policy_detail = {
                        '策略ID': policy_id,
                        '描述': policy['Policy'].get('Description', '无描述'),
                        '状态': policy['Policy'].get('State', '未知'),
                        '执行角色': policy['Policy'].get('ExecutionRoleArn', '未知'),
                        '目标标签': [],
                        '时间表': []
                    }
                    
                    # 获取策略目标标签
                    policy_details = policy['Policy'].get('PolicyDetails', {})
                    if isinstance(policy_details, list):
                        policy_details = policy_details[0] if policy_details else {}
                    
                    for selector in policy_details.get('ResourceTypes', []):
                        if selector == 'VOLUME':
                            target_tags = policy_details.get('TargetTags', [])
                            policy_detail['目标标签'] = [f"{tag.get('Key', '')}={tag.get('Value', '')}" for tag in target_tags]
                    
                    # 获取时间表信息
                    schedules = policy_details.get('Schedules', [])
                    for schedule in schedules:
                        create_rule = schedule.get('CreateRule', {})
                        retain_rule = schedule.get('RetainRule', {})
                        schedule_info = {
                            '名称': schedule.get('Name', '未知'),
                            '创建时间': f"从{create_rule.get('Times', ['未知'])[0]}开始每隔{create_rule.get('Interval', '未知')}{create_rule.get('IntervalUnit', '')}",
                            '保留数量': f"保留{retain_rule.get('Interval', '未知')}{retain_rule.get('IntervalUnit', '')}"
                        }
                        policy_detail['时间表'].append(schedule_info)
                    
                    policies.append(policy_detail)
            except Exception as e:
                print(f"获取策略 {policy_id} 详情时发生错误: {str(e)}")
                print(f"错误类型: {type(e)}")
                import traceback
                print("详细错误信息:")
                print(traceback.format_exc())
                continue
                
        return policies
    except Exception as e:
        print(f"获取生命周期管理器策略时发生错误: {str(e)}")
        print(f"错误类型: {type(e)}")
        import traceback
        print("详细错误信息:")
        print(traceback.format_exc())
        return None

#获取未启用快照的卷信息
def get_volumes_without_snapshot():
    try:
        ec2 = boto3.client('ec2')
        volumes = []
        
        # 获取所有卷
        paginator = ec2.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for volume in page['Volumes']:
                # 检查是否有snapshot标签且值为true
                has_snapshot_tag = False
                for tag in volume.get('Tags', []):
                    if tag['Key'].lower() == 'snapshot' and tag['Value'].lower() == 'true':
                        has_snapshot_tag = True
                        break
                
                # 如果没有snapshot标签或值不为true，收集卷信息
                if not has_snapshot_tag:
                    volume_info = {
                        '卷ID': volume['VolumeId'],
                        '创建时间': volume['CreateTime'].strftime('%Y-%m-%d %H:%M:%S'),
                        '大小(GB)': volume['Size'],
                        '状态': volume['State'],
                        '类型': volume['VolumeType'],
                        '可用区': volume['AvailabilityZone'],
                        '加密': '是' if volume.get('Encrypted', False) else '否',
                        '标签': [f"{tag['Key']}={tag['Value']}" for tag in volume.get('Tags', [])]
                    }
                    
                    # 获取关联的实例信息
                    if volume.get('Attachments'):
                        volume_info['关联实例'] = volume['Attachments'][0].get('InstanceId', '未知')
                        volume_info['挂载点'] = volume['Attachments'][0].get('Device', '未知')
                    else:
                        volume_info['关联实例'] = '未挂载'
                        volume_info['挂载点'] = '未挂载'
                    
                    volumes.append(volume_info)
                    
        return volumes
    except Exception as e:
        print(f"获取卷信息时发生错误: {str(e)}")
        return None

def export_to_markdown(data, title, filename, timestamp=None):
    """通用Markdown导出函数"""
    if timestamp is None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f'# {title}\n\n')
        f.write(f'> 生成时间: {timestamp}\n\n')
        
        if isinstance(data, dict):
            f.write('| 类型 | 数量 |\n|------|------|\n')
            for key, value in data.items():
                f.write(f'| {key} | {value} |\n')
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    # 处理生命周期策略
                    if '策略ID' in item:
                        f.write(f'## 策略: {item.get("策略ID")}\n\n')
                        f.write(f'- 描述: {item.get("描述")}\n')
                        f.write(f'- 状态: {item.get("状态")}\n')
                        f.write(f'- 执行角色: {item.get("执行角色")}\n')
                        
                        # 输出目标标签
                        if item.get('目标标签'):
                            f.write('- 目标标签:\n')
                            for tag in item['目标标签']:
                                f.write(f'  - {tag}\n')
                        
                        # 输出时间表
                        if item.get('时间表'):
                            f.write('- 时间表:\n')
                            for schedule in item['时间表']:
                                f.write(f'  - 名称: {schedule.get("名称")}\n')
                                f.write(f'    创建时间: {schedule.get("创建时间")}\n')
                                f.write(f'    保留数量: {schedule.get("保留数量")}\n')
                        f.write('\n---\n\n')
                    
                    # 处理卷信息
                    elif '卷ID' in item:
                        f.write(f'## 卷: {item.get("卷ID")}\n\n')
                        f.write(f'- 创建时间: {item.get("创建时间")}\n')
                        f.write(f'- 大小: {item.get("大小(GB)")} GB\n')
                        f.write(f'- 状态: {item.get("状态")}\n')
                        f.write(f'- 类型: {item.get("类型")}\n')
                        f.write(f'- 可用区: {item.get("可用区")}\n')
                        f.write(f'- 加密: {item.get("加密")}\n')
                        f.write(f'- 关联实例: {item.get("关联实例")}\n')
                        f.write(f'- 挂载点: {item.get("挂载点")}\n')
                        
                        # 输出标签
                        if item.get('标签'):
                            f.write('- 标签:\n')
                            for tag in item['标签']:
                                f.write(f'  - {tag}\n')
                        f.write('\n---\n\n')
                    
                    # 处理普通告警信息
                    else:
                        # 处理安全组信息
                        if '安全组ID' in item:
                            f.write(f'## {item.get("名称", "未知")} ({item.get("安全组ID", "未知")})\n\n')
                            f.write(f'- VPC ID: {item.get("VPC ID", "默认VPC")}\n')
                            f.write(f'- 描述: {item.get("描述", "无描述")}\n\n')
                            
                            # 输出入站规则
                            if item.get('入站规则'):
                                f.write('### 入站规则\n\n')
                                f.write('| 协议 | 端口范围 | 源 |\n|------|----------|----------|\n')
                                for rule in item['入站规则']:
                                    f.write(f'|{rule["协议"]}|{rule["端口范围"]}|{rule["源/目标"]}')
                                f.write('\n')
                            
                            # 输出出站规则
                            if item.get('出站规则'):
                                f.write('### 出站规则\n\n')
                                f.write('| 协议 | 端口范围 | 目标 |\n|------|----------|----------|\n')
                                for rule in item['出站规则']:
                                    f.write(f'|{rule["协议"]}|{rule["端口范围"]}|{rule["源/目标"]}')
                                f.write('\n')
                            
                            f.write('---\n\n')
                        else:
                            f.write(f'## {item.get("名称", "未知")}\n\n')
                            for key, value in item.items():
                                if key == '历史记录' and value:  # 特殊处理历史记录
                                    f.write('### 历史记录\n\n')
                                    f.write('| 时间 | 状态 | 值 |\n|------|------|----------|\n')
                                    for record in value:
                                        f.write(f'| {record["时间"]} | {record["状态"]} | {record["详细信息"].replace("value: ", "")} |\n')
                                    f.write('\n')
                                elif key != '历史记录' and key != '名称':  # 其他信息正常显示
                                    f.write(f'- {key}: {value}\n')
                            f.write('\n')

def export_to_excel(security_groups, filename):
    try:
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # 导出安全组信息
                df_sg = pd.DataFrame(security_groups)
                df_sg.to_excel(writer, sheet_name='安全组', index=False)
        
        return True
    except Exception as e:
        print(f"导出Excel文件时发生错误: {str(e)}")
        return False


def main():
    # 创建输出目录
    export_path = Path('aws_reports')
    export_path.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 导出资源统计
    print("\n正在导出资源统计...")
    if resource_counts := get_aws_resource_counts():
        filename = f'{export_path}/aws_resources_{timestamp}.md'
        export_to_markdown(resource_counts, 'AWS 资源统计', filename)
        print(f"已导出资源统计到: {filename}")
    
    # 导出告警信息
    print("\n正在导出告警信息...")
    if alarms := get_alarm_details():
        filename = f'{export_path}/aws_alarms_{timestamp}.md'
        export_to_markdown(alarms, 'AWS CloudWatch告警', filename)
        print(f"已导出告警信息到: {filename}")
    
    # 导出安全组信息
    print("\n正在导出安全组信息...")
    if security_groups := get_security_group_details():
        filename = f'{export_path}/aws_security_groups_{timestamp}.md'
        export_to_markdown(security_groups, 'AWS 安全组配置', filename)
        print(f"已导出安全组信息到: {filename}")
    
    # 导出WAF信息
    print("\n正在导出WAF信息...")
    if waf_info := get_waf_details():
        filename = f'{export_path}/aws_waf_{timestamp}.md'
        export_to_markdown(waf_info, 'AWS WAF配置', filename)
        print(f"已导出WAF信息到: {filename}")
    
    # 导出安全建议
    print("\n正在导出安全建议...")
    severity_levels = ["CRITICAL","HIGH"]
    
    if findings := get_security_findings(severity_levels):
        filename = f'{export_path}/aws_security_{timestamp}.md'
        export_to_markdown(findings, 'AWS 安全建议', filename)
        print(f"已导出安全建议到: {filename}")
    
    # 导出生命周期管理器策略
    print("\n正在导出生命周期管理器策略...")
    if dlm_policies := get_dlm_policy_details():
        filename = f'{export_path}/aws_dlm_policies_{timestamp}.md'
        export_to_markdown(dlm_policies, 'AWS 生命周期管理器策略', filename)
        print(f"已导出生命周期管理器策略到: {filename}")
    
    # 导出未启用快照的卷信息
    print("\n正在导出未启用快照的卷信息...")
    if volumes := get_volumes_without_snapshot():
        filename = f'{export_path}/aws_volumes_without_snapshot_{timestamp}.md'
        export_to_markdown(volumes, 'AWS 未启用快照的卷信息', filename)
        print(f"已导出未启用快照的卷信息到: {filename}")

    #6
if __name__ == "__main__":
    main() 
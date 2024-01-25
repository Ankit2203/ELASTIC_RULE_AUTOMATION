class ParamGenerator:

    def __init__(self,rule_temp_param, rule_entry):
        self.rule_temp_param = rule_temp_param
        self.rule_entry = rule_entry
        self.comparator = {'Is above or equals' : '>=',
                           'Is above' : '>',
                           'Is below' : '<',
                           'Is below or equals' : '<=',
                           'Is between' : 'between'
                           }
    
    def anomaly_param(self):
        self.rule_temp_param['anomalySeverityType'] = self.rule_entry.get('SEVERITY','')
        self.rule_temp_param['environment'] = self.rule_entry.get('ENVIRONMENT','')
        self.rule_temp_param['serviceName'] = self.rule_entry.get('SERVICE','')
        self.rule_temp_param['transactionType'] = self.rule_entry.get('TYPE','')
        return self.rule_temp_param, 'apm.anomaly'

    def latency_param(self):
        self.rule_temp_param['aggregationType'] = self.rule_entry.get("WHEN",'').replace(" percentile", "")
        self.rule_temp_param['threshold'] = int(self.rule_entry.get('IS ABOVE',''))
        self.rule_temp_param['windowUnit'] = self.rule_entry.get('WINDOW UNIT',' ')[0]
        self.rule_temp_param['windowSize'] = int(self.rule_entry.get('FOR THE LAST',''))
        self.rule_temp_param['environment'] = self.rule_entry.get('ENVIRONMENT','')
        self.rule_temp_param['serviceName'] = self.rule_entry.get('SERVICE','')
        self.rule_temp_param['transactionType'] = self.rule_entry.get('TYPE','')
        return self.rule_temp_param, 'apm.transaction_duration'

    def error_count_param(self):
        self.rule_temp_param['threshold'] = int(self.rule_entry.get('IS ABOVE',''))
        self.rule_temp_param['windowUnit'] = self.rule_entry.get('WINDOW UNIT',' ')[0]
        self.rule_temp_param['windowSize'] = int(self.rule_entry.get('FOR THE LAST',''))
        self.rule_temp_param['environment'] = self.rule_entry.get('ENVIRONMENT','')
        self.rule_temp_param['serviceName'] = self.rule_entry.get('SERVICE','')
        return self.rule_temp_param, 'apm.error_rate'

    def fail_transact_param(self):
        self.rule_temp_param['threshold'] = int(self.rule_entry.get('IS ABOVE',''))
        self.rule_temp_param['windowUnit'] = self.rule_entry.get('WINDOW UNIT',' ')[0]
        self.rule_temp_param['windowSize'] = int(self.rule_entry.get('FOR THE LAST',''))
        self.rule_temp_param['environment'] = self.rule_entry.get('ENVIRONMENT','')
        self.rule_temp_param['serviceName'] = self.rule_entry.get('SERVICE','')
        self.rule_temp_param['transactionType'] = self.rule_entry.get('TYPE','')
        return self.rule_temp_param, 'apm.transaction_error_rate'
    
    def log_threshold_param(self):
        self.rule_temp_param['timeSize'] = self.rule_entry.get('TIME SIZE','')
        self.rule_temp_param['timeUnit'] = self.rule_entry.get('TIME UNIT',' ')[0]
        self.rule_temp_param['count']['value'] = self.rule_entry.get('COUNT VALUE','')
        self.rule_temp_param['count']['comparator'] = self.rule_entry.get('COUNT COMPARATOR','')
        self.rule_temp_param['criteria'] = [{
                                              "comparator": "",
                                              "field": "",
                                              "value": 0
                                            }]
        if self.rule_entry.get('LOG ENTRIES', '') == 'ratio':
            self.rule_temp_param['criteria'].append(self.rule_temp_param.get('criteria')[0])
            self.rule_temp_param['criteria'][1]['comparator'] = self.rule_entry.get('CRITERIA COMPARATOR 1', '')
            self.rule_temp_param['criteria'][1]['field'] = self.rule_entry.get('CRITERIA FIELD 1', '')
            self.rule_temp_param['criteria'][1]['value'] = self.rule_entry.get('CRITERIA COMP VALUE 1', '')
        self.rule_temp_param['criteria'][0]['comparator'] = self.rule_entry.get('CRITERIA COMPARATOR', '')
        self.rule_temp_param['criteria'][0]['field'] = self.rule_entry.get('CRITERIA FIELD', '')
        self.rule_temp_param['criteria'][0]['value'] = self.rule_entry.get('CRITERIA COMP VALUE', '')
        #self.rule_temp_param['groupBy'] = [self.rule_entry['GROUP BY']]
        self.rule_temp_param['groupBy'] = [grp.strip() for grp in self.rule_entry.get('GROUP BY').split(',')]
        return self.rule_temp_param, 'logs.alert.document.count'
    
    def anomaly_detection_param(self):
        self.rule_temp_param['severity'] = self.rule_entry.get('SEVERITY SCALE', '')
        self.rule_temp_param['resultType'] = self.rule_entry.get('RESULT TYPE', '')
        self.rule_temp_param['includeInterim'] = self.rule_entry.get('INTERIM', '')
        #self.rule_temp_param["jobSelection"]['jobIds'].append(self.rule_entry['JOB ID'])
        self.rule_temp_param["jobSelection"]['jobIds'] = [jobid.strip() for jobid in self.rule_entry.get('JOB ID', '').split(',')]
        #self.rule_temp_param["jobSelection"]['groupIds'].append(self.rule_entry['GROUP ID'])
        self.rule_temp_param["jobSelection"]['groupIds'] = [grpid.strip() for grpid in self.rule_entry.get('GROUP ID', '').split(',')]
        self.rule_temp_param['topNBuckets'] = self.rule_entry.get('TOP N BUCKETS', '')
        self.rule_temp_param['lookbackInterval'] = (str(self.rule_entry.get('LOOK BACK INTERVAL', ''))+self.rule_entry.get('INTERVAL UNIT', ' ')[0])
        return self.rule_temp_param, 'xpack.ml.anomaly_detection_alert'
    
    def elasticsearch_query_param(self):
        self.rule_temp_param['timeField'] = self.rule_entry.get('TIMEFIELD', '')
        self.rule_temp_param['timeWindowSize'] = self.rule_entry.get('TIME WINDOW SIZE', '')
        self.rule_temp_param['timeWindowUnit'] = self.rule_entry.get('TIME_UNIT', ' ')[0]
        self.rule_temp_param['threshold'] = [self.rule_entry.get('THRESHOLD', '')]
        if self.rule_entry['THRESHOLD COMPARATOR'] == 'Is between':
            self.rule_temp_param['threshold'].append(self.rule_entry.get('THRESHOLD UPPER BOUND', ''))
        self.rule_temp_param['thresholdComparator'] = self.comparator[self.rule_entry.get('THRESHOLD COMPARATOR', '')]
        self.rule_temp_param['size'] = self.rule_entry.get('SIZE', '')
        self.rule_temp_param['searchType'] = self.rule_entry.get('SEARCH TYPE', '')
        self.rule_temp_param['index'] = [indx.strip() for indx in self.rule_entry.get('INDEX', '').split(',')]
        self.rule_temp_param['esQuery'] = self.rule_entry.get('ES QUERY', '')
        return self.rule_temp_param, '.es-query'
    
    def index_threshold_param(self):
        self.rule_temp_param['timeField'] = self.rule_entry.get('TIMEFIELD', '')
        self.rule_temp_param['timeWindowSize'] = self.rule_entry.get('TIME WINDOW SIZE', '')
        self.rule_temp_param['timeWindowUnit'] = self.rule_entry.get('TIME_UNIT', ' ')[0]
        self.rule_temp_param['threshold'] = [self.rule_entry.get('THRESHOLD', '')]
        if self.rule_entry['THRESHOLD COMPARATOR'] == 'Is between':
            self.rule_temp_param['threshold'].append(self.rule_entry.get('THRESHOLD UPPER BOUND', ''))
        self.rule_temp_param['thresholdComparator'] = self.comparator[self.rule_entry.get('THRESHOLD COMPARATOR', '')]
        self.rule_temp_param['index'] = [indx.strip() for indx in self.rule_entry.get('INDEX', '').split(',')]
        self.rule_temp_param['groupBy'] = self.rule_entry.get('GROUP_BY', '')
        if self.rule_temp_param['groupBy'] != 'all':
            self.rule_temp_param['termField'] = self.rule_entry.get('TERM FIELD', '')
            self.rule_temp_param['termSize'] = self.rule_entry.get('TERM SIZE', '')
        self.rule_temp_param['aggType'] = self.rule_entry.get('AGGREGATE TYPE', '')
        if self.rule_temp_param['aggType'] != 'count':
            self.rule_temp_param['aggField'] = self.rule_entry.get('AGGREGATE FIELD', '')
        return self.rule_temp_param, ".index-threshold"
    
    def transform_health_param(self):
        self.rule_temp_param['includeTransforms'] = [val.strip() for val in self.rule_entry.get('INCLUDE TRANSFORM', '').split(',')]
        return self.rule_temp_param, 'transform_health'
        #self.rule_temp_param['excludeTransforms'] = self.rule_entry.get('EXCLUDE TRANSFORM', '')
        #self.rule_temp_param['testsConfig'] = self.rule_entry.get('TESTSCONFIG', '')
    
    def usage_param(self):
        self.rule_temp_param['duration'] = str(self.rule_entry.get('TIME WINDOW SIZE', ''))+self.rule_entry.get('TIME_UNIT', ' ')[0]
        self.rule_temp_param['threshold'] = self.rule_entry.get('THRESHOLD', '')
        rule_id = {'CPU Usage': 'monitoring_alert_disk_usage',
                   'Disk Usage': 'monitoring_alert_disk_usage'
                   }
        return self.rule_temp_param, rule_id.get(self.rule_entry['Rule ID'])
    
    def ccr_read_param(self):
        self.rule_temp_param['duration'] = str(self.rule_entry.get('TIME WINDOW SIZE', ''))+self.rule_entry.get('TIME_UNIT', ' ')[0]
        return self.rule_temp_param, 'monitoring_ccr_read_exceptions'

    def no_param(self):
        rule_id = {'Cluster health': 'monitoring_alert_cluster_health',
                   'Elasticsearch version mismatch': 'monitoring_alert_elasticsearch_version_mismatch',
                   'Kibana version mismatch': 'monitoring_alert_kibana_version_mismatch'}
        return {}, rule_id.get(self.rule_entry['Rule ID'])

    


        
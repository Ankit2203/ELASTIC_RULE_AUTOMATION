BASE_TEMPLATE = {
    "params": "",
    "consumer": "alerts",
    "rule_type_id": "",
    "enabled": True,
    "schedule":{},
    "actions": [],
    "tags":[],
    "notify_when": "",
    "name": "",
    "throttle": ""
}

ELASTIC_URL = "https://mec-poc-deployment.kb.us-east-1.aws.found.io:"

ELASTIC_PORT = 9243

RULE_CREATION_API = "/api/alerting/rule/"

ELASTIC_HEADER = {
    "kbn-xsrf": "True",
    "Authorization": "Basic ZWxhc3RpYzpKdVRqODh3WHpRTVFGU0JObWpGSExqNXc=",
    "Content-Type": "application/json"
}

RULE_TEMP_FILE = "PROG/rule_param_template.json"

INPUT_FILE = "PROG/INPUT/ELASTIC_ALERT_RULES.xlsm"

NOTIFY = {
    "Only on status change": 'onActionGroupChange',
    "Every time ruke is active": "onActiveAlert",
    "On a custom action interval":  "onThrottleInterval"
}

WEBHOOK_CONNECTORS = { 
    "alert payload": "ea96caf0-08e4-11ed-be1f-7b5cc6c2e804",
    "aws-event-api": "9f38c2d0-4ee4-11ec-8d41-8f3c725f1524",
    "event-enricher-faast": "21395600-4885-11ee-8a71-6f58acc996f3",
    "event-enricher-saasf": "03134300-3dab-11ee-8a71-6f58acc996f3",
    "event-handler": "02bc49f0-0329-11ed-be1f-7b5cc6c2e804",
    "Moog_test": "9ad20550-06b0-11ee-84d1-818aaf217d36",
    "moogsoft_elasticalert": "980f7850-fdfc-11ed-84d1-818aaf217d36",
    "Moogsoft_FaaST_infra_alerts": "d5444290-0b4a-11ee-84d1-818aaf217d36",
    "moogsoft-webhook": "1ca6a8b0-01c6-11ed-be1f-7b5cc6c2e804",
    "moogsoft-webhook-prd": "bc970e20-fa2a-11ed-84d1-818aaf217d36",
    "qa-eventhandler": "033996b0-ea5c-11ed-a011-794b8adf50bf",
    "xcellent_care_ro": "26fa9570-23c5-11ee-ab03-2f54fe6e66d7"
}

MASTER_SHEET = "RECORDS/ELASTIC_ALERT_RULES_MASTER.xlsx"

INPUT_FILE_MASTER_COPY = "RECORDS/ELASTIC_ALERT_RULES.xlsm"

RULE_IDs = {
    'Anomaly' : 'apm.anomaly',
    'Latency threshold' : 'apm.transaction_duration',
    'Error count threshold' : 'apm.error_rate',
    'Failed transaction rate threshold' : 'apm.transaction_error_rate',
    'Log Threshold': 'logs.alert.document.count',
    'Anomaly detection alert': 'xpack.ml.anomaly_detection_alert',
    'Elasticsearch query': '.es-query',
    'Index threshold': '.index-threshold',
    'Transform health': 'transform_health',
    'CPU Usage': 'monitoring_alert_disk_usage',
    'Disk Usage': 'monitoring_alert_disk_usage',
    'CCR read exceptions': 'monitoring_ccr_read_exceptions',
    'Cluster health': 'monitoring_alert_cluster_health',
    'Elasticsearch version mismatch': 'monitoring_alert_elasticsearch_version_mismatch',
    'Kibana version mismatch': 'monitoring_alert_kibana_version_mismatch'
}

MAIL_TEMP = {
    "id": "elastic-cloud-email",
    "group":"recovered",
    "params": {
      "message": "",
      "to": [],
      "subject": ""
    }
} 

WEEBHOOK_TEMP = {
    "id": "",
    "group": "",
    "params": {
       "body": ""
    }
}

RULE_CHECK_API = '/internal/alerting/rules/_find?page=1&per_page=10&search_fields=["name","tags"]&search='
RULE_CHECK_API_ARG = '&default_search_operator=AND&sort_field=name&sort_order=asc'

COMPARATOR = {
    'Is above or equals' : '>=',
    'Is above' : '>',
    'Is below' : '<',
    'Is below or equals' : '<=',
    'Is between' : 'between'
}

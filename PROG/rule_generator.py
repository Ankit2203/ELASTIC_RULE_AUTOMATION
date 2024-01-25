import json
import pandas as pd
import requests
import os
import shutil

from param_generator import ParamGenerator


class RuleGenerator:

    def __init__(self):
        self.base_template = {
                              "params": "",
                              "consumer": "alerts",
                              "rule_type_id": "",
                              "enabled": False,
                              "schedule":{},
                              "actions": [],
                              "tags":[],
                              "notify_when": "",
                              "name": "",
                              "throttle": ""
                            }
        
        self.url = "https://mec-poc-deployment.kb.us-east-1.aws.found.io:9243/api/alerting/rule/"

        self.headers = {
                        "kbn-xsrf": "True",
                        "Authorization": "Basic ZWxhc3RpYzpKdVRqODh3WHpRTVFGU0JObWpGSExqNXc=",
                        "Content-Type": "application/json"
                       }
    
    def load_param_temp(self):
        rule_template = "PROG/rule_param_template.json"
        print("Reading rule params from file : {} \n".format(rule_template.split("/")[-1]), "-"*60, sep ='')
        rule_template_file = open(rule_template)
        rule_temp = json.load(rule_template_file)
        return rule_temp['rules']
    
    def csv_reader(self):
        rule_sheet = "PROG/INPUT/ELASTIC_ALERT_RULES.xlsm"
        print("Reading input from file : {} \n".format(rule_sheet.split("/")[-1]), "-"*60, sep='')
        rule_df = pd.read_excel(rule_sheet).iloc[:, 1:]
        return rule_df

    def generate_rule_json(self):
        print("Generation of rules starts \n", "-"*40, sep='')
        rule_temp = self.load_param_temp()
        rule_df = self.csv_reader()
        input_df_pass = pd.DataFrame(columns=rule_df.columns)
        input_df_fail = pd.DataFrame(columns=rule_df.columns)
        for cnt, row in rule_df.iterrows():
            print("Rule Name = {0}, Rule ID = {1} \n".format(row['Name'], row['Rule ID']), "="*60, sep='')
            if self.check_rule_exist(row['Name']):
                input_df_fail.loc[len(input_df_fail)] = row
                input_df_fail['status'] = 'Pre Existing Rule Name'
                continue
            base_temp = self.base_template.copy()
            rule_name = row['Rule ID']
            rule_temp_param = rule_temp[rule_name] if rule_name in rule_temp.keys() else {}
            self.fill_base_temp(base_temp, row)
            base_temp["params"], rule_id = self.fill_params(rule_temp_param, row, rule_name)
            base_temp['rule_type_id'] = rule_id
            self.base_template.copy().clear()
            resp = self.create_rule(base_temp)
            if resp.status_code == 200:
                input_df_pass.loc[len(input_df_pass)] = row
                input_df_pass['status'] = "Success [Resp code: "+ str(resp.status_code) +" ]"
                print("rule name = {0} status = {1}".format(rule_name, input_df_pass['status']))
            else:
                input_df_fail.loc[len(input_df_fail)] = row
                input_df_fail['status'] = resp.text
                print("rule name = {0} status = {1}".format(rule_name, input_df_fail['status']))
            print("-"*60)
        print(row)
        self.update_masterSheet(input_df_pass, input_df_fail)
        
    def fill_base_temp(self, base_temp, row):
        print("Filling the Base template \n", "-"*60, sep='')
        notify = {"Only on status change": 'onActionGroupChange',
                  "Every time ruke is active": "onActiveAlert",
                  "On a custom action interval":  "onThrottleInterval"}
        base_temp['name'] = row['Name']
        base_temp['tags'] = [tag.strip() for tag in row['Tags'].split(',')]
        base_temp["notify_when"] = notify[row['Notify']]
        base_temp['throttle'] = None if base_temp["notify_when"] != "onThrottleInterval" else (str(row['Throttle']).replace('.0', '')+row['Throttle Unit'][0])    
        base_temp["schedule"] = {"interval": str(row["Check every"]).replace('.0', '') + row["Time Unit"][0]}
        base_temp['actions'] = self.fill_base_temp_action(row)

    def fill_base_temp_action(self, row):
        print("Filling the actions requried to be triggred : ", end=" ")
        action = []
        mail = {
                "id": "elastic-cloud-email",
                "group":"recovered",
                "params": {
                  "message": "",
                  "to": [],
                  "subject": ""
                }
            } 
        webhook = {
                    "id": "",
                    "group": "",
                    "params": {
                       "body": ""
                    }
                }
        webhook_connectors = { 
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
        if row['Actions'] == 'Mail' or row['Actions'] == 'both':
            print("Mail",end= " ")
            mail['params']["message"] = row['Mail-Message']
            mail['params']['to'] = [mail.strip() for mail in row['Mail-Receiver'].split(',')]
            mail['params']['subject'] = row['Mail-Subject']
            mail['group'] = row['Mail-Group']
            action.append(mail)
        if row['Actions'] == 'Webhook' or row['Actions'] == 'both':
            print("Webhook", sep = '')
            webhook['group'] = row['Webhook-Group']
            webhook['params']['body'] = row['Webhook-Body']
            webhook['id'] = webhook_connectors[row['Webhook-Connector']]
            action.append(webhook)
        print("\n","-"*60)
        return action

    def fill_params(self, rule_temp_param, rule_entry, rule_name):
        par_gen = ParamGenerator(rule_temp_param, rule_entry)
        param_dict = {
            'Anomaly' : par_gen.anomaly_param,
            'Latency threshold' : par_gen.latency_param,
            'Error count threshold' : par_gen.error_count_param,
            'Failed transaction rate threshold' : par_gen.fail_transact_param,
            'Log Threshold': par_gen.log_threshold_param,
            'Anomaly detection alert': par_gen.anomaly_detection_param,
            'Elasticsearch query': par_gen.elasticsearch_query_param,
            'Index threshold': par_gen.index_threshold_param,
            'Transform health': par_gen.transform_health_param,
            'CPU Usage': par_gen.usage_param,
            'Disk Usage': par_gen.usage_param,
            'CCR read exceptions': par_gen.ccr_read_param,
            'Cluster health' : par_gen.no_param,
            'Elasticsearch version mismatch': par_gen.no_param,
            'Kibana version mismatch': par_gen.no_param
        }
        print("call method = {} for filling rule params\n".format(rule_name), "-"*60, sep='')
        return param_dict.get(rule_name)()
    
    def create_rule(self, base_temp):
        #import pdb; pdb.set_trace()
        print("send payload request to fill rules\n", "-"*60, sep='')

        payload = json.dumps(base_temp)
        #print("payload")
        print("payload \n", "-"*60, "\n", payload, "\n", "-"*60, sep='')
        response = requests.post(self.url, headers=self.headers, json=payload)
        print("Response Status Code = {}\n".format(response.status_code), "-"*60, sep='')
        return response
    
    def update_masterSheet(self, input_df_pass, input_df_fail):
        file_path = "RECORDS/ELASTIC_ALERT_RULES_MASTER.xlsx"
        print("updating master sheet = {}\n".format(file_path.split("/")[-1]), "-"*60, sep='')
    
        # Read existing 'success' sheet
        try:
            df_success = pd.read_excel(file_path, sheet_name='success', engine='openpyxl')
        except FileNotFoundError:
            df_success = pd.DataFrame()
    
        # Concatenate new data with existing 'success' data
        merged_df_pass = pd.concat([df_success, input_df_pass], ignore_index=True)
    
        # Read existing 'failed' sheet
        try:
            df_failed = pd.read_excel(file_path, sheet_name='failed', engine='openpyxl')
        except FileNotFoundError:
            df_failed = pd.DataFrame()
    
        # Concatenate new data with existing 'failed' data
        merged_df_fail = pd.concat([df_failed, input_df_fail], ignore_index=True)
    
        # Write updated DataFrames back to Excel sheets
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            merged_df_pass.to_excel(writer, index=False, sheet_name='success')
            merged_df_fail.to_excel(writer, index=False, sheet_name='failed')
    
    def check_rule_exist(self, name):
        url = 'https://mec-poc-deployment.kb.us-east-1.aws.found.io:9243/internal/alerting/rules/_find?page=1&per_page=10&search_fields=["name","tags"]&search='+ name +'&default_search_operator=AND&sort_field=name&sort_order=asc'
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            exist = json.loads(response.__dict__['_content'].decode('utf-8')).get('data')
            if exist:
                print('rule = {} exists'.format(name))
                return True
            else:
                print('rule = {} doest not exists'.format(name))
        else:
            print(f"Error: {response.status_code} - {response.text}")
        return False
    

    def replace_file(self):
        source_file = "RECORDS/ELASTIC_ALERT_RULES.xlsm"
        destination_file = "PROG/INPUT/ELASTIC_ALERT_RULES.xlsm"
        # Check if the source file exists
        if not os.path.exists(source_file):
            print(f"Source file '{source_file}' does not exist.")
            return
    
        # Check if the destination file exists
        if os.path.exists(destination_file):
            # If the destination file exists, delete it
            os.remove(destination_file)
    
        # Copy the source file to the destination
        shutil.copy2(source_file, destination_file)

if __name__ == "__main__":
    rule_gen = RuleGenerator()
    rule_gen.generate_rule_json()

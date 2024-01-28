import json
import pandas as pd
import requests
import os
import shutil

from param_generator import ParamGenerator
from rule_config import BASE_TEMPLATE, ELASTIC_URL, ELASTIC_PORT, \
    ELASTIC_HEADER, RULE_CREATION_API, RULE_TEMP_FILE, INPUT_FILE, \
    NOTIFY, WEBHOOK_CONNECTORS, MASTER_SHEET, RULE_IDs, MAIL_TEMP, \
    WEEBHOOK_TEMP, RULE_CHECK_API, RULE_CHECK_API_ARG, INPUT_FILE_MASTER_COPY


class RuleGenerator:


    def __init__(self):
        self.base_template = BASE_TEMPLATE
    
    def load_param_temp(self):

        # PRINT STAEMENT
        print("Reading rule params from file : {} \n".format(
            RULE_TEMP_FILE.split("/")[-1]), "-"*60, sep ='')

        rule_template_file = open(RULE_TEMP_FILE)
        rule_temp = json.load(rule_template_file)
        return rule_temp['rules']
    
    def input_reader(self):
        # PRINT STATEMENT
        print("Reading input from file : {} \n".format(
            INPUT_FILE.split("/")[-1]), "-"*60, sep='')
        
        rule_df = pd.read_excel(INPUT_FILE).iloc[:, 1:]
        return rule_df

    def generate_rule_json(self):
        # PRINT STATEMENT
        print("Generation of rules starts \n", "-"*40, sep='')

        # call to get rules template
        rule_temp = self.load_param_temp()
        # call to get input file
        rule_df = self.input_reader()

        # create data frames for success and failed requests
        input_df_pass = pd.DataFrame(columns=rule_df.columns)
        input_df_fail = pd.DataFrame(columns=rule_df.columns)

        #iterating through input rows and send rule creation request
        for cnt, row in rule_df.iterrows():
            # PRINT STATEMENT
            print("count = {2} Rule Name = {0}, Rule ID = {1} \n".format(
                row['Name'], row['Rule ID'], cnt), "="*60, sep='')

            # check for rule existence
            if self.check_rule_exist(row['Name']):
                input_df_fail.loc[len(input_df_fail)] = row
                input_df_fail['status'] = 'Pre Existing Rule Name'
                continue

            base_temp = self.base_template.copy()
            rule_name = row['Rule ID']
            rule_temp_param = rule_temp[rule_name
                              ] if rule_name in rule_temp.keys() else {}
            
            # call to fill base template
            self.fill_base_temp(base_temp, row)
            # call to fill rule template
            base_temp["params"] = self.fill_params(rule_temp_param, row,
                                                   rule_name)
            
            base_temp['rule_type_id'] = RULE_IDs[rule_name]
            self.base_template.copy().clear()

            # send request for rule creation
            resp = self.create_rule(base_temp)

            # updating data frames for master sheet - success, failed
            # success records success entries failed sheet records failed entries
            if resp.status_code == 200:
                input_df_pass.loc[len(input_df_pass)] = row
                input_df_pass['status'] = "Success [Resp code: "+ str(
                    resp.status_code) +" ]"
                
                # PRINT STATEMENT
                print("rule name = {0} status = {1}".format(
                    rule_name, input_df_pass['status']))
            else:
                input_df_fail.loc[len(input_df_fail)] = row
                input_df_fail['status'] = resp.text
                
                # PRINT STATEMENT
                print("rule name = {0} status = {1}".format(
                    rule_name, input_df_fail['status']))
                
            # PRINT STATEMENT
            print("-"*60)
        
        # update master sheet
        self.update_masterSheet(input_df_pass, input_df_fail)

        #replace input file with master copy
        print("replace input file with master copy")
        self.replace_input_file()
        
    def fill_base_temp(self, base_temp, row):
        # PRINT STATEMENT
        print("Filling the Base template \n", "-"*60, sep='')
        
        # fill rule - name, tags, notification_condition
        base_temp['name'] = row['Name']
        base_temp['tags'] = [tag.strip() for tag in row['Tags'].split(',')]
        base_temp["notify_when"] = NOTIFY[row['Notify']]

        # fill throttle value as per row['Notify']
        base_temp['throttle'] = None if base_temp["notify_when"
            ] != "onThrottleInterval" else (
            str(row['Throttle']).replace('.0', '')+row['Throttle Unit'][0])  
        
        base_temp["schedule"] = {"interval": str(row["Check every"]).replace(
            '.0', '') + row["Time Unit"][0]}
        
        # fill actions template
        base_temp['actions'] = self.fill_base_temp_action(row)

    def fill_base_temp_action(self, row):
        # PRINT ACTIONS
        print("Filling the actions requried to be triggred : ", end=" ")

        action = []
        mail = MAIL_TEMP
        webhook = WEEBHOOK_TEMP
        
        # fill action template
        if row['Actions'] == 'Mail' or row['Actions'] == 'both':
            print("Mail",end= " ")
            mail['params']["message"] = row.get('Mail-Message', '')
            mail['params']['to'] = [mail.strip() for mail in row.get(
                'Mail-Receiver', '').split(',')]
            mail['params']['subject'] = row.get('Mail-Subject', '')
            mail['group'] = row.get('Mail-Group', '')
            action.append(mail)

        # fill webhook template
        if row['Actions'] == 'Webhook' or row['Actions'] == 'both':
            print("Webhook", sep = '')
            webhook['group'] = row.get('Webhook-Group', '')
            webhook['params']['body'] = row.get('Webhook-Body', '')
            webhook['id'] = WEBHOOK_CONNECTORS.get(row.get(
                'Webhook-Connector', ''), '')
            action.append(webhook)

        # PRINT STAEMENT
        print("\n","-"*60)

        return action

    def fill_params(self, rule_temp_param, rule_entry, rule_name):
        # create instance for ParamGenerator (class with methods for filling rule param template)
        par_gen = ParamGenerator(rule_temp_param, rule_entry)
        # map rule id name with method to fill particular rule
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

        # PRINT STATEMENT
        print("call method = {} for filling rule params\n".format(
            rule_name), "-"*60, sep='')
        
        # call mapped method and get the filled template for rule params
        return param_dict.get(rule_name)()
    
    def create_rule(self, base_temp):
        # PRINT STATEMENT
        print("send payload request to fill rules\n", "-"*60, sep='')

        # convert rule input to json
        payload = json.dumps(base_temp)

        # PRINT PAYLOAD
        print("payload \n", "-"*60, "\n", payload, "\n", "-"*60, sep='')

        # create url for sending create request
        url = ELASTIC_URL + str(ELASTIC_PORT) + RULE_CREATION_API
        # send rule creation request to elastic
        response = requests.post(url, headers=ELASTIC_HEADER, json=payload)
        
        # PRINT REPOSNSE CODE
        print("Response Status Code = {}\n".format(
            response.status_code), "-"*60, sep='')
        
        # return response
        return response
    
    def update_masterSheet(self, input_df_pass, input_df_fail):
        # PRINT MASTER SHEET NAME 
        print("updating master sheet = {}\n".format(
            MASTER_SHEET.split("/")[-1]), "-"*60, sep='')
        
        # Read existing 'success' sheet
        try:
            df_success = pd.read_excel(
                MASTER_SHEET, sheet_name='success', engine='openpyxl')
        except FileNotFoundError:
            df_success = pd.DataFrame()
    
        # Concatenate new data with existing 'success' data
        merged_df_pass = pd.concat([df_success, input_df_pass], 
                                   ignore_index=True)
    
        # Read existing 'failed' sheet
        try:
            df_failed = pd.read_excel(MASTER_SHEET, sheet_name='failed',
                                     engine='openpyxl')
        except FileNotFoundError:
            df_failed = pd.DataFrame()
    
        # Concatenate new data with existing 'failed' data
        merged_df_fail = pd.concat([df_failed, input_df_fail],
                                    ignore_index=True)
    
        # Write updated DataFrames back to Excel sheets
        with pd.ExcelWriter(MASTER_SHEET, engine='openpyxl') as writer:
            merged_df_pass.to_excel(writer, index=False, sheet_name='success')
            merged_df_fail.to_excel(writer, index=False, sheet_name='failed')
    
    def check_rule_exist(self, name):
        url = ELASTIC_URL + str(ELASTIC_PORT
                                ) + RULE_CHECK_API + name + RULE_CHECK_API_ARG
        response = requests.get(url, headers=ELASTIC_HEADER)
        if response.status_code == 200:
            exist = json.loads(response.__dict__['_content'].decode(
                'utf-8')).get('data')
            if exist:
                print('rule = {} exists'.format(name))
                return True
            else:
                print('rule = {} doest not exists'.format(name))
        else:
            # PRINT RESPONSE CODE and MESSAGE if request fails
            print(f"Error: {response.status_code} - {response.text}")
        return False
   
    def replace_input_file(self):
        # replace input file with master
        source_file = INPUT_FILE_MASTER_COPY
        destination_file = INPUT_FILE
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

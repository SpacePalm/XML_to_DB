from airflow import DAG
from airflow.operators.python import PythonOperator, BranchPythonOperator
from airflow.operators.bash_operator import BashOperator
from airflow.hooks.base_hook import BaseHook
from airflow.decorators import dag, task
from airflow.utils.dates import days_ago
from datetime import datetime, timedelta, date
import requests
import pandas as pd
from bs4 import BeautifulSoup
import clickhouse_connect
import os
import json

project_path = '/opt/airflow/dags/CVE_SQL/'
db_hook = BaseHook.get_connection('Clickhouse')
connection = clickhouse_connect.get_client(host = db_hook.host, port = 8123, username = db_hook.login, password = db_hook.password, database = db_hook.schema)
proxy_hook = BaseHook.get_connection('proxy')
proxies = {
    'http': f'{proxy_hook.schema}{proxy_hook.login}:{proxy_hook.password}@{proxy_hook.host}:{proxy_hook.port}',
    'https': f'{proxy_hook.schema}{proxy_hook.login}:{proxy_hook.password}@{proxy_hook.host}:{proxy_hook.port}'
    
}


def setup_data():
    try:
        connection.query('select cve from cve_data')
        
    except:
        
        doc_year = 2020
        doc_month = [8, 9, 10, 11, 12, 1, 2, 3, 4, 5, 6, 7]
        while doc_year != date.today().year + 1:
            print(doc_year)
            for month in doc_month:
                get_load_data(month, doc_year)
                load_db_data()
            doc_year+=1


def get_load_data(today_m = date.today().month, today_y = date.today().year):
    
    vulnerability_db = {"VulnerabilityID":[],"DocXMLDate":[], "Ordinal":[], "CVE":[], "Title":[], "CWE":[], "CWE_text":[]}
    vulnerability_db_status = {"VulnerabilityFK":[], "StatusType": [], "ProductID":[]}
    vulnerability_db_notes = {"VulnerabilityFK":[], "NotesTitle":[], "NotesType":[], "NotesOrdinal":[], "Note":[]}
    vulnerability_db_threats = {"VulnerabilityFK":[], "TreatsType":[], "Description":[], "ProductID":[]}
    vulnerability_db_score_set = {"VulnerabilityFK":[],"BaseScore":[], "TemporalScore":[], "Vector":[], 'ProductID':[]}
    vulnerability_db_acknowledgment= {"VulnerabilityFK":[], "Name":[], "URL":[]}
    vulnerability_db_revision = {"VulnerabilityFK":[], "Number":[], 'Date':[], 'Description':[]}
    vulnerability_db_Remediations={"VulnerabilityFK":[], "KB":[], "Type":[], 'URL':[], "ProductID":[], 'SubType':[], 'FixedBuild':[]}
    
    productdb = {'ProductID':[], 'ProductName':[], 'productdbType':[], 'productdbName':[]}
    
    notes_db = {"DocumentIDFK":[], "NoteID": [], "notes_dbTitle":[], "notes_dbAudience":[], "notes_dbType":[], "Ordinal":[]}
    
    document_info_db = {"DocumentID":[], "Alias":[], 'Status':[], "Version":[], "RevisionHistoryNumber":[], "RevisionHistoryDate":[], 
                        "RevisionHistoryDescription":[], "InitialReleaseDate":[], "CurrentReleaseDate":[], 'Pubishertype':[], 'ContactDetails':[], 'IssuingAuthority':[], 
                        'DocumentTitle':[], 'DocumentType':[], 'vuln':[],'dc':[],'cvrf-common':[],'prod':[],'scap-core':[],'cvssv2':[],'cpe-lang':[],'sch':[],'cvrf':[]}
    
    
    
    doc_month_array = {8 :"Aug",9: "Sep",10: 'Oct',11: "Nov",12: "Dec",1: "Jan",2: 'Feb',3: "Mar",4: "Apr",5: "May",6: "Jun",7: "Jul"}
    # doc_year_array = ['2023', '2024']
                
    soup = ""
    url = f'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{today_y}-{doc_month_array[today_m]}'

    # Получаем данные по ссылке
    response = requests.get(url, proxies = proxies)
    
    # Проверка успешности запроса
    if response.status_code == 200:
        print(f"{today_y}-{doc_month_array[today_m]}")
        document_info_date = f"{today_y}-{doc_month_array[today_m]}"
        soup = BeautifulSoup(response.content, "xml")
        
    
    
        
    else:
        print("Не удалось получить данные, статус код:", response.status_code)
        return
        
    
    
    
    library = soup.find('ProductTree')
    
    def process_node(node, productdb):
    
        if node.name is not None:
            if 'ProductID' in node.attrs:
                productdb['ProductID'].append(node.attrs['ProductID'])
                productdb['ProductName'].append(node.text)
            
            if 'Type' not in node.attrs and node.name != 'ProductTree':
                if 'Type' in node.parent.attrs:
                    productdb['productdbType'].append(node.parent.attrs['Type'])
                    productdb['productdbName'].append(node.parent.attrs['Name'])
                else:
                    productdb['productdbType'].append('')
                    productdb['productdbName'].append('')
    
            for child in node.children:
                process_node(child, productdb)
    
    
    process_node(library, productdb)
    
    def process_vulnerability(node, vulnerability_db, vulnerability_index):
        vulnerability_db['Ordinal'].append(node.get('Ordinal'))
        vulnerability_db['Title'].append(node.find('Title').text if node.find('Title').text else '')
        vulnerability_db['CVE'].append(node.find('CVE').text)
        vulnerability_db['VulnerabilityID'].append(vulnerability_index+1)
        vulnerability_db['DocXMLDate'].append(document_info_date)
        vulnerability_db['CWE_text'].append(node.find('CWE').text if node.find('CWE') else '')
        vulnerability_db['CWE'].append( node.find('CWE').get('ID') if node.find('CWE') else '')
            
    
    def process_status(node, vulnerability_db_status, vulnerability_index):
        vulnerability_db_status['ProductID'].append(node.text)
        vulnerability_db_status['StatusType'].append(node.parent.get('Type'))
        vulnerability_db_status['VulnerabilityFK'].append(vulnerability_index)
    
    def process_notes(node, vulnerability_db_notes, vulnerability_index):
        vulnerability_db_notes['VulnerabilityFK'].append(vulnerability_index)
        vulnerability_db_notes['NotesTitle'].append(node.get('Title'))
        vulnerability_db_notes['NotesType'].append(node.get('Type'))
        vulnerability_db_notes['NotesOrdinal'].append(node.get('Ordinal'))
        vulnerability_db_notes['Note'].append(node.text)
    
    def process_threats(node, vulnerability_db_threats, vulnerability_index):
        vulnerability_db_threats['VulnerabilityFK'].append(vulnerability_index)
        vulnerability_db_threats['TreatsType'].append(node.get('Type'))
        product_id = node.find('ProductID')
        vulnerability_db_threats['ProductID'].append(product_id.text if product_id else '')
        description = node.find('Description')
        vulnerability_db_threats['Description'].append(description.text if description else '')
    
    def process_score_set(node, vulnerability_db_score_set, vulnerability_index):
        vulnerability_db_score_set['VulnerabilityFK'].append(vulnerability_index)
        vulnerability_db_score_set['BaseScore'].append(node.find('BaseScore').text)
        vulnerability_db_score_set['TemporalScore'].append(node.find('TemporalScore').text)
        vulnerability_db_score_set['Vector'].append(node.find('Vector').text)
        vulnerability_db_score_set['ProductID'].append(node.find('ProductID').text)
    
    def process_acknowledgment(node, vulnerability_db_acknowledgment, vulnerability_index):
        vulnerability_db_acknowledgment['VulnerabilityFK'].append(vulnerability_index)
        name = node.find('Name')
        vulnerability_db_acknowledgment['Name'].append(name.text if name and name.text else '')
        url = node.find('URL')
        vulnerability_db_acknowledgment['URL'].append(url.text if url and url.text else '')
    
    def process_revision(node, vulnerability_db_revision, vulnerability_index):
        vulnerability_db_revision['VulnerabilityFK'].append(vulnerability_index)
        vulnerability_db_revision['Number'].append(node.find('Number').text)
        vulnerability_db_revision['Date'].append(node.find('Date').text)
        vulnerability_db_revision['Description'].append(node.find('Description').text if node.find('Description').text else '')
    
    def process_Remediations(node, vulnerability_db_Remediations, vulnerability_index):
        vulnerability_db_Remediations['VulnerabilityFK'].append(vulnerability_index)
        vulnerability_db_Remediations['KB'].append(node.find('Description').text if node.find('Description').text.isdigit() else '')
        vulnerability_db_Remediations['Type'].append(node.get('Type'))
        vulnerability_db_Remediations['URL'].append(node.find('URL').text if node.find('URL') else '')
        vulnerability_db_Remediations['ProductID'].append([tag.text for tag in node.find_all('ProductID')])
        vulnerability_db_Remediations['SubType'].append(node.find('SubType').text if node.find('SubType') else '')
        vulnerability_db_Remediations['FixedBuild'].append(node.find('FixedBuild').text if node.find('FixedBuild') else '')
    
        for child in node.children:
            vulnerability_db
    
    
    def vulnerability(node, vulnerability_db):
        if node.name is None:
            return
        
        vulnerability_index = len(vulnerability_db['Ordinal']) - 1
        
    
        if node.name == 'Vulnerability' and 'Ordinal' in node.attrs:
            process_vulnerability(node, vulnerability_db, vulnerability_index)
        elif node.name == 'ProductID' and node.parent.name == "Status":
            process_status(node, vulnerability_db_status, vulnerability_index)
        elif node.name == 'Note' and node.parent.name == "Notes":
            process_notes(node, vulnerability_db_notes, vulnerability_index)
        elif node.name == 'Threat' and node.parent.name == "Threats":
            process_threats(node, vulnerability_db_threats, vulnerability_index)
        elif node.name == 'ScoreSet' and node.parent.name == "CVSSScoreSets":
            process_score_set(node, vulnerability_db_score_set, vulnerability_index)
        elif node.name == 'Acknowledgment' and node.parent.name == 'Acknowledgments':
            process_acknowledgment(node, vulnerability_db_acknowledgment, vulnerability_index)
        elif node.name == 'Revision' and node.parent.name == 'RevisionHistory':
            process_revision(node, vulnerability_db_revision, vulnerability_index)
        elif node.name == 'Remediation' and node.parent.name == 'Remediations':
            process_Remediations(node, vulnerability_db_Remediations, vulnerability_index)
        
    
        for child in node.children:
            vulnerability(child, vulnerability_db)
    
    
    lib = soup.find('cvrfdoc').children
    for child in lib:
        if child.name == "Vulnerability":
            vulnerability(child, vulnerability_db)
            
    
    def documen_tracking(node,document_info_db):
        if node.name is None:
            return
        
        if node.name == "ID" and node.parent.name == "Identification":
            document_info_db['DocumentID'].append(document_info_date)
        elif node.name == "Alias" and node.parent.name == "Identification":
            document_info_db["Alias"].append(node.text if node.text else '')
        elif node.name == "Status" and node.parent.name == "DocumentTracking":
            document_info_db["Status"].append(node.text if node.text else '')
        elif node.name == "Version" and node.parent.name == "DocumentTracking":
            document_info_db["Version"].append(node.text if node.text else '')
        elif node.name == "Number" and node.parent.name == "Revision":
            document_info_db["RevisionHistoryNumber"].append(node.text if node.text else '')
        elif node.name == "Date" and node.parent.name == "Revision":
            document_info_db["RevisionHistoryDate"].append(node.text if node.text else '')
        elif node.name == "Description" and node.parent.name == "Revision":
            document_info_db["RevisionHistoryDescription"].append(node.text if node.text else '')
        elif node.name == "InitialReleaseDate" and node.parent.name == "DocumentTracking":
            document_info_db["InitialReleaseDate"].append(node.text if node.text else '')
        elif node.name == "CurrentReleaseDate" and node.parent.name == "DocumentTracking":
            document_info_db["CurrentReleaseDate"].append(node.text if node.text else '')
    
    
        for child in node.children:
            documen_tracking(child, document_info_db) 
    
    def documen_publisher(node,document_info_db):
        if node.name is None:
            return
        
        if node.name == 'DocumentPublisher' and node.parent.name == 'cvrfdoc':
            document_info_db['Pubishertype'].append(node.get('Type'))
        if node.name == 'ContactDetails' and node.parent.name == 'DocumentPublisher':
            document_info_db['ContactDetails'].append(node.text if node.text else '')
        if node.name == 'IssuingAuthority' and node.parent.name == 'DocumentPublisher':
            document_info_db['IssuingAuthority'].append(node.text if node.text else '')
    
        for child in node.children:
            documen_publisher(child, document_info_db) 
    
    lib = soup.find('cvrfdoc')
    
    document_info_db['vuln'].append(lib.get('xmlns:vuln'))
    document_info_db['dc'].append(lib.get('xmlns:dc'))
    document_info_db['cvrf-common'].append(lib.get('xmlns:cvrf-common'))
    document_info_db['scap-core'].append(lib.get('xmlns:scap-core'))
    document_info_db['prod'].append(lib.get('xmlns:prod'))
    document_info_db['cvssv2'].append(lib.get('xmlns:cvssv2'))
    document_info_db['cpe-lang'].append(lib.get('xmlns:cpe-lang'))
    document_info_db['sch'].append(lib.get('xmlns:sch'))
    document_info_db['cvrf'].append(lib.get('xmlns:cvrf'))
    
    lib = soup.find('cvrfdoc').children
    for child in lib:
        if child.name == "DocumentTracking":
            documen_tracking(child, document_info_db)
        if child.name == "DocumentPublisher":
            documen_publisher(child, document_info_db)
        if child.name == 'DocumentTitle':
            document_info_db['DocumentTitle'].append(child.text if child.text else '')
        if child.name == 'DocumentType':
            document_info_db['DocumentType'].append(child.text if child.text else '')
    
        
    
    with open(f"{project_path}df.json", 'w') as f:
        df_json = {
            'vulnerability_db': vulnerability_db,
            'vulnerability_db_status': vulnerability_db_status,
            'vulnerability_db_notes': vulnerability_db_notes,
            'vulnerability_db_threats': vulnerability_db_threats,
            'vulnerability_db_score_set': vulnerability_db_score_set,
            'vulnerability_db_acknowledgment': vulnerability_db_acknowledgment,
            'vulnerability_db_revision': vulnerability_db_revision,
            'vulnerability_db_Remediations': vulnerability_db_Remediations,
            'productdb': productdb,
            'notes_db': notes_db,
            'document_info_db': document_info_db
        }
    
        json.dump(df_json, f)
    
    
        
def load_db_data():
    with open(f"{project_path}df.json", 'r') as f:
        df_json = json.load(f)
    
    productdb = df_json['productdb']
    vulnerability_db = df_json['vulnerability_db']
    vulnerability_db_status = df_json['vulnerability_db_status']
    vulnerability_db_notes = df_json['vulnerability_db_notes']
    vulnerability_db_threats = df_json['vulnerability_db_threats']
    vulnerability_db_score_set = df_json['vulnerability_db_score_set']
    vulnerability_db_acknowledgment = df_json['vulnerability_db_acknowledgment']
    vulnerability_db_revision = df_json['vulnerability_db_revision']
    vulnerability_db_Remediations = df_json['vulnerability_db_Remediations']
    notes_db = df_json['notes_db']
    document_info_db = df_json['document_info_db']
    
    productdb = pd.DataFrame(productdb)
    vulnerability_db = pd.DataFrame(vulnerability_db)
    vulnerability_db_status = pd.DataFrame(vulnerability_db_status)
    vulnerability_db_notes = pd.DataFrame(vulnerability_db_notes)
    vulnerability_db_threats = pd.DataFrame(vulnerability_db_threats)
    vulnerability_db_score_set = pd.DataFrame(vulnerability_db_score_set)
    vulnerability_db_acknowledgment = pd.DataFrame(vulnerability_db_acknowledgment)
    vulnerability_db_revision = pd.DataFrame(vulnerability_db_revision)
    vulnerability_db_Remediations = pd.DataFrame(vulnerability_db_Remediations)
    notes_db = pd.DataFrame(notes_db)
    document_info_db = pd.DataFrame(document_info_db)
    
    
    
    def run_query(filename):
        with open(project_path + filename, 'r') as f:
            query = f.read()
            query = query.split(';')
            for i in query:
                connection.query(i)
    for i in ['CreateTable.sql', 'Clear.sql']:
        run_query(i)
    
    vulnerability_db.drop(columns=['Ordinal'], inplace = True)
    vulnerability_db_notes.drop(columns=['NotesOrdinal'], inplace = True)
    productdb.drop(columns=['productdbName'], inplace = True)
    document_info_db.drop(columns=['Alias'], inplace = True)
    
    # vulnerability_db_revision['Date'] = pd.to_datetime(vulnerability_db_revision['Date'])
    document_info_db['RevisionHistoryDate'] = pd.to_datetime(document_info_db['RevisionHistoryDate'])
    document_info_db['InitialReleaseDate'] = pd.to_datetime(document_info_db['InitialReleaseDate'])
    document_info_db['CurrentReleaseDate'] = pd.to_datetime(document_info_db['CurrentReleaseDate'])
    
    
    
    connection.insert_df('vulnerability_status', vulnerability_db_status, column_names = ["vulnerability_fk", 'status_type', 'product_id'])
    connection.insert_df('vulnerability_notes', vulnerability_db_notes, column_names = ["vulnerability_fk", 'title', 'notes_type', 'note'])
    connection.insert_df('vulnerability_threats', vulnerability_db_threats, column_names = ["vulnerability_fk", 'threats_type', 'description', 'product_id'])
    connection.insert_df('vulnerability_score_set', vulnerability_db_score_set, column_names = ["vulnerability_fk", 'base_score', 'temporal_score', 'vector', 'product_id'])
    connection.insert_df('vulnerability_revision', vulnerability_db_revision, column_names = ["vulnerability_fk", 'number', 'revision_date', 'description'])
    connection.insert_df('vulnerability_remediation', vulnerability_db_Remediations, column_names = ["vulnerability_fk", 'kb', 'remediation_type', 'url','product_id','subtype', 'fixed_build'])
    connection.insert_df('product', productdb, column_names = ['id', "product_name", 'product_type'])
    connection.insert_df('document_info', document_info_db, column_names = ["id", 'status', 'version', 'revision_history_number', 'revision_history_date', 'revision_history_description'
                                                                            , 'initial_relise_date', 'current_relise_date', 'publisher_type', 'contact_details'
                                                                            , 'issuring_authority', 'document_title', 'document_type', 'vlun'
                                                                            , 'dc', 'cvrf_common', 'prod', 'scap_core', 'cvssv2', 'cpe_lang', 'sch', 'cvrf'])
    connection.insert_df('vulnerability', vulnerability_db, column_names = ["id", 'doc_xml_date', 'cve', 'title', 'cwe', 'cwe_text'])


def transform_data():

    allowed_val = ["Windows 10", 'Windows Server 2008','Windows 8', 'Windows 7', 'Windows Server 2012', 'Windows 11', 'Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022', 'Windows Server']
    oc_month_array = {8 :"Aug",9: "Sep",10: 'Oct',11: "Nov",12: "Dec",1: "Jan",2: 'Feb',3: "Mar",4: "Apr",5: "May",6: "Jun",7: "Jul"}
    
    msrc = connection.query_df("""Select distinct product_names, doc_xml_date, doc_initial_relise_date,  kb, cve from msrc_data where cve not like 'ADV%'""")
    print("Got msrc")
    osquery_patches = connection.query_df('select distinct hostname, hotfix_id, installed_on from dwh_osquery_software_patches where toMonth(timestamp) >= toMonth(now()) -1 ')
    print("Got osquery_patches")
    osquery_version = connection.query_df('Select distinct * from dict_osquery_system_os_version where toMonth(timestamp) >= toMonth(now()) -1')
    print("Got osquery_version")

    osquery_patches['hotfix_id'] = osquery_patches['hotfix_id'].str.lstrip('KB').astype(int)
    osquery_patches = osquery_patches.loc[osquery_patches.groupby('hostname')['hotfix_id'].idxmax()]

    msrc['kb'] = msrc['kb'].astype(int)

    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows 10' if x.startswith('Windows 10') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows Server 2008' if x.startswith('Windows Server 2008') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows 7' if x.startswith('Windows 7') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows 8' if x.startswith('Windows 8') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows Server 2012' if x.startswith('Windows Server 2012') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows 11' if x.startswith('Windows 11') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows Server 2016' if x.startswith('Windows Server 2016') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows Server 2019' if x.startswith('Windows Server 2019') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows Server 2022' if x.startswith('Windows Server 2022') else x)
    msrc['product_names'] = msrc['product_names'].apply(lambda x: 'Windows Server' if x.startswith('Windows Server, version') else x)

    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows 10' if "Windows 10" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows Server 2019' if "Windows Server 2019" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows Server 2012' if "Windows Server 2012" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows Server 2016' if "Windows Server 2016" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows Server 2008' if "Windows Server 2008" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows 7' if "Windows 7" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows 11' if "Windows 11" in x else x)
    osquery_version['os_name'] = osquery_version['os_name'].apply(lambda x:'Windows 8' if "Windows 8" in x else x)

    msrc = msrc[msrc['product_names'].isin(allowed_val)]

    msrc = msrc.sort_values(by = ['product_names', 'kb'])

    res = (msrc.groupby('product_names')
       .apply(lambda x: sorted(x[['kb', 'doc_initial_relise_date']].drop_duplicates().assign(doc_initial_relise_date = x['doc_initial_relise_date'].dt.strftime('%Y-%m-%d')).values.tolist(), key = lambda y: y[1]))
       .reset_index(name = "kb_arr"))

    def rem_kb(arr):
        un_kb = {}
        for kb, time in arr:
            if kb not in un_kb or time > un_kb[kb]:
                un_kb[kb] = time
        return sorted([[kb, un_kb[kb]] for kb in un_kb], key= lambda x: x[0])

    res['kb_arr'] = res['kb_arr'].apply(rem_kb)

    msrc = msrc.sort_values(by = 'kb')

    osquery_version = pd.merge(osquery_version, res, left_on = 'os_name', right_on = 'product_names', how = 'left')
    osquery_version = pd.merge(osquery_version, osquery_patches, on = 'hostname', how = 'left')

    def trim_array(row):
        arr = row['kb_arr']
        kb = row['hotfix_id']

        
        if not isinstance(arr, list) : return []
        last_month = datetime.strptime(arr[-1][1], '%Y-%m-%d').date().month
        last_year = datetime.strptime(arr[-1][1], '%Y-%m-%d').date().year
        for i in range(len(arr)): 
            if arr[i][0] > kb and datetime.strptime(arr[i][1], '%Y-%m-%d').date().month == last_month and datetime.strptime(arr[i][1], '%Y-%m-%d').date().year == last_year: 
                return arr[i:]
    
        return []
                

    osquery_version['kb_arr'] = osquery_version.apply(trim_array, axis = 1)


    def get_cve(row):
        if row[ 'kb_arr'] == []: return []
            
        return msrc[(msrc['kb'] > row['hotfix_id']) & (msrc['product_names'] == row['os_name'])]['cve'].unique()
        
    osquery_version['cve'] = osquery_version.apply(get_cve, axis = 1)

    msrc_date = msrc[['kb', 'doc_xml_date']].drop_duplicates()
    msrc_date['doc_xml_date'] = pd.to_datetime(msrc_date['doc_xml_date'], format = '%Y-%b') 
    msrc_date.sort_values(by = 'doc_xml_date', ascending = False, inplace = True)
    msrc_date = msrc_date.drop_duplicates(subset= ['kb'])
    msrc_date['doc_xml_date'] = msrc_date['doc_xml_date'].dt.strftime('%Y-%b')
    osquery_version = osquery_version.merge(msrc_date, left_on = 'hotfix_id', right_on = 'kb', how = 'left')
    osquery_version = osquery_version.explode('cve')

    osquery_version['install_date'] = pd.to_datetime(osquery_version['install_date'], unit='s')

    osquery_version['hotfix_id'] = osquery_version['hotfix_id'].astype(str)
    osquery_version['doc_xml_date'] = osquery_version['doc_xml_date'].astype(str)
    osquery_version['install_date'] = osquery_version['install_date'].astype(str)
    osquery_version['cve'] = osquery_version['cve'].astype(str)
    osquery_version['kb_arr'] = osquery_version['kb_arr'].apply(lambda x: [[str(sublist[0]), sublist[1]] if len(sublist)>1 else sublist for sublist in x])
    osquery_version['hotfix_id'] = osquery_version['hotfix_id'].apply(lambda x: x[:-2] if len(x) > 0  and x!= 'nan' else '')
    osquery_version['doc_xml_date'] = osquery_version['doc_xml_date'].apply(lambda x: x if x!= 'nan' else '')
    osquery_version['cve'] = osquery_version['cve'].apply(lambda x: x if x!= 'nan' else '')

    osquery_version['hostname'].replace([None], '', inplace = True)
    osquery_version['codename'].replace([None], '', inplace = True)
    osquery_version['version'].replace([None], '', inplace = True)
    osquery_version['hotfix_id'].replace([None], '', inplace = True)
    osquery_version['doc_xml_date'].replace([None], '', inplace = True)
    osquery_version['install_date'].replace([None], '', inplace = True)
    osquery_version['kb_arr'].replace([None], '', inplace = True)
    osquery_version['cve'].replace([None], '', inplace = True)
    
    res = osquery_version[['hostname', 'codename', 'version', 'hotfix_id', 'doc_xml_date', 'install_date', 'kb_arr', 'cve']]

    res.to_json(f"{project_path}kb_hosts.json", orient="records", force_ascii=False)





def load_rec_data():
    res = pd.read_json(f"{project_path}kb_hosts.json", orient="records")

    connection.insert_df('dwh_osquery_hosts_kb', res, column_names = ['hostname', 'os_name', 'os_version', 'last_kb', 'last_kb_date', 'last_update_date', 'rec_kb_arr', 'cve'])

with DAG  (
    'msrc_data_dag',
    start_date=datetime(2024, 1, 1),
    max_active_runs=1,
	schedule_interval='@daily',
    tags=["dmurashov"],
	catchup=False,

):
                
    set_data = PythonOperator(
        task_id = 'setup_db',
        python_callable = setup_data
    ) 
    
    get_data = PythonOperator(
        task_id = 'get_data',
        python_callable = get_load_data
    )
    
    load_data = PythonOperator(
        task_id = 'load_data',
        python_callable = load_db_data
    )

    transform_osquery = PythonOperator(
        task_id = 'transform_osquery_data',
        python_callable = transform_data
    )

    load_osquery_kb = PythonOperator(
        task_id = 'load_osquery_kb_data',
        python_callable = load_rec_data
    )
  
BashOperator(task_id='start_dag', bash_command='echo “Start DAG”')>> set_data >> get_data >> load_data >> transform_osquery >> load_osquery_kb



        
    
    


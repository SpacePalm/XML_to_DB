from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash_operator import BashOperator
from airflow.hooks.base_hook import BaseHook
from airflow.decorators import dag, task
from airflow.utils.dates import days_ago
from datetime import datetime, timedelta
import requests
import pandas as pd
from bs4 import BeautifulSoup
import clickhouse_connect
import os

connection = clickhouse_connect.get_client(host = "10.80.131.73", port = 8123, username = 'test', password = 'secretPassword321!', database = 'test')


@dag (
    'test_dag',
    start_date=datetime(2024, 1, 1),
    max_active_runs=3,
	schedule_interval='@hourly',
    tags=["dmurashov"],
	catchup=False,

)
def main_dag():
    t = BashOperator(task_id='bash_hello_world', bash_command='echo “Hello World”')

    @task(task_id = 'get_data')
    def get_load_data():
        document_info_index = 0
        document_info_date = ''
        
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
        
        def product_tree(soup, productdb):
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
        
        
        
        
        
        def Get_Vulnerability(soup, vulnerability_db, vulnerability_db_status, vulnerability_db_notes, vulnerability_db_threats, vulnerability_db_score_set,vulnerability_db_acknowledgment, vulnerability_db_revision):
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
        
        def Get_DocumentNotes(soup, notes_db):
            def document_notes(node, notes_db):
                if node.name is None:
                    return
                notes_index = len(notes_db['notes_dbAudience'])
                if node.name == 'Note' and node.parent.name == 'DocumentNotes':
                    notes_db["DocumentIDFK"].append(document_info_index)
                    notes_db["notes_dbTitle"].append(node.get('Title'))
                    notes_db["notes_dbAudience"].append(node.get('Audience'))
                    notes_db["notes_dbType"].append(node.get('Type'))
                    notes_db["Ordinal"].append(node.get('Ordinal'))
                    notes_db["NoteID"].append(notes_index)
                
                for child in node.children:
                    document_notes(child, notes_db) 
                
        
            lib = soup.find('cvrfdoc').children
            for child in lib:
                if child.name == "DocumentNotes":
                    document_notes(child, notes_db)
        
        def Doc_Info(soup, document_info_db):
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
        
        
        
        # doc_month_array = ["Aug","Sep",'Oct', "Nov", "Dec", "Jan", 'Feb', "Mar", "Apr", "May", "Jun", "Jul"]
        # doc_year_array = ['2023', '2024']
        
        for i in ['2023']:
            for j in ['Jul']:
                soup = ""
                proxy_hook = BaseHook.get_connection('proxy')
                proxies = {
                    'http': f'{proxy_hook.schema}{proxy_hook.login}:{proxy_hook.password}@{proxy_hook.host}:{proxy_hook.port}',
                    'https': f'{proxy_hook.schema}{proxy_hook.login}:{proxy_hook.password}@{proxy_hook.host}:{proxy_hook.port}'
                    
                }
                url = f'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{i}-{j}'
        
                # Получаем данные по ссылке
                response = requests.get(url, proxies = proxies)
        
                # Проверка успешности запроса
                if response.status_code == 200:
                    print(f"{i}-{j}")
                    document_info_date = f"{i}-{j}"
                    document_info_index +=1
                    soup = BeautifulSoup(response.content, "xml")
                    product_tree(soup, productdb)
                    Get_Vulnerability(soup, vulnerability_db, vulnerability_db_status, vulnerability_db_notes, vulnerability_db_threats, vulnerability_db_score_set,vulnerability_db_acknowledgment, vulnerability_db_revision)
                    Get_DocumentNotes(soup, notes_db)
                    Doc_Info(soup, document_info_db)
        
        
                    
                else:
                    print("Не удалось получить данные, статус код:", response.status_code)
            
        
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
        
        cve_table = vulnerability_db['CWE'].unique()
        
        with open('/opt/airflow/dags/CVE_SQL/CreateTable.sql', 'r') as f:
            query = f.read()
            f.close()
        query = query.split(';')
        for i in query:
            connection.query(i)
            
        with open('/opt/airflow/dags/CVE_SQL/Clear.sql', 'r') as f:
            query = f.read()
            f.close()
        query = query.split(';')
        for i in query:
            connection.query(i) 
        
        vulnerability_db.drop(columns=['Ordinal'], inplace = True)
        vulnerability_db_notes.drop(columns=['NotesOrdinal'], inplace = True)
        productdb.drop(columns=['productdbName'], inplace = True)
        document_info_db.drop(columns=['Alias'], inplace = True)
        
        vulnerability_db_revision['Date'] = pd.to_datetime(vulnerability_db_revision['Date'])
        document_info_db['RevisionHistoryDate'] = pd.to_datetime(document_info_db['RevisionHistoryDate'])
        document_info_db['InitialReleaseDate'] = pd.to_datetime(document_info_db['InitialReleaseDate'])
        document_info_db['CurrentReleaseDate'] = pd.to_datetime(document_info_db['CurrentReleaseDate'])
        
        vulnerability_db_status['id'] = range(0, len(vulnerability_db_status))
        vulnerability_db_notes['id'] = range(0, len(vulnerability_db_notes))
        vulnerability_db_threats['id'] = range(0, len(vulnerability_db_threats))
        vulnerability_db_score_set['id'] = range(0, len(vulnerability_db_score_set))
        vulnerability_db_revision['id'] = range(0, len(vulnerability_db_revision))
        vulnerability_db_Remediations['id'] = range(0, len(vulnerability_db_Remediations))
        
        
        connection.insert_df('vulnerability_status', vulnerability_db_status, column_names = ["vulnerability_fk", 'status_type', 'product_id', 'id'])
        connection.insert_df('vulnerability_notes', vulnerability_db_notes, column_names = ["vulnerability_fk", 'title', 'notes_type', 'note', 'id'])
        connection.insert_df('vulnerability_threats', vulnerability_db_threats, column_names = ["vulnerability_fk", 'threats_type', 'description', 'product_id', 'id'])
        connection.insert_df('vulnerability_score_set', vulnerability_db_score_set, column_names = ["vulnerability_fk", 'base_score', 'temporal_score', 'vector', 'product_id', 'id'])
        connection.insert_df('vulnerability_revision', vulnerability_db_revision, column_names = ["vulnerability_fk", 'number', 'revision_date', 'description', 'id'])
        connection.insert_df('vulnerability_remediation', vulnerability_db_Remediations, column_names = ["vulnerability_fk", 'kb', 'remediation_type', 'url','product_id','subtype', 'fixed_build', 'id'])
        connection.insert_df('product', productdb, column_names = ['id', "product_name", 'product_type'])
        connection.insert_df('document_info', document_info_db, column_names = ["id", 'status', 'version', 'revision_history_number', 'revision_history_date', 'revision_history_description'
                                                                                , 'initial_relise_date', 'current_relise_date', 'publisher_type', 'contact_details'
                                                                                , 'issuring_authority', 'document_title', 'document_type', 'vlun'
                                                                                , 'dc', 'cvrf_common', 'prod', 'scap_core', 'cvssv2', 'cpe_lang', 'sch', 'cvrf'])
        connection.insert_df('vulnerability', vulnerability_db, column_names = ["id", 'doc_xml_date', 'cve', 'title', 'cwe', 'cwe_text'])
    get_data = get_load_data()
    t >> get_data
    
main_dag()

CREATE TABLE if not exists vulnerability(

id UInt64,
doc_xml_date Nullable(String),
cve Nullable(String),
title Nullable(String),
cwe Nullable(String),
cwe_text Nullable(String)

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists vulnerability_status(

id UInt64,
vulnerability_fk UInt64,
status_type String,
product_id String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists vulnerability_notes(

id UInt64,
vulnerability_fk UInt64,
title  Nullable(String),
notes_type  Nullable(String),
note  Nullable(String)

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists vulnerability_threats(

id UInt64,
vulnerability_fk UInt64,
title String,
threats_type String,
description String,
product_id String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists vulnerability_score_set(

id UInt64,
vulnerability_fk UInt64,
base_score String,
temporal_score String,
vector String,
product_id String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists vulnerability_revision(

id UInt64,
vulnerability_fk UInt64,
number String,
revision_date DateTime,
description String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists vulnerability_remediation(

id UInt64,
vulnerability_fk UInt64,
kb String,
remediation_type String,
url String,
product_id Array(String),
subtype String,
fixed_build String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists product(

id String,
product_name String,
product_type String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE if not exists document_info(

id String,
status String,
version String,
revision_history_number UInt16,
revision_history_date DateTime,
revision_history_description String,
initial_relise_date DateTime,
current_relise_date DateTime,
publisher_type String,
contact_details String,
issuring_authority String,
document_title String,
document_type String,
vlun String,
dc String,
cvrf_common String,
prod String,
scap_core String,
cvssv2 String,
cpe_lang String,
sch String,
cvrf String,

)
ENGINE = MergeTree
ORDER BY id;













create table if not exists cve_data
engine = ReplacingMergeTree(timestamp)
order by (cve, doc_xml_date)
settings allow_nullable_key = 1
as
WITH
  vuln_remediation as (
    SELECT vulnerability_fk, 
    arrayDistinct(groupArray(kb)) as kb,
    arrayDistinct(groupArray(fixed_build)) as fixed_build 
    FROM vulnerability_remediation 
    GROUP BY vulnerability_fk
  ),
  vuln_threats as (
    SELECT vulnerability_fk, 
    arrayDistinct(groupArray(threats_type)) as threats_type, 
    arrayDistinct(groupArray(description)) as description 
    FROM vulnerability_threats 
    GROUP BY vulnerability_fk
  ),
  max_revision as (
    select
      max(revision_date) as revision_date,
      max(toFloat32(number)) as number,
      vulnerability_fk,
    from vulnerability_revision
    GROUP BY vulnerability_fk
  ),
  vuln_revision as (
    select
      mr.vulnerability_fk as vulnerability_fk,
      mr.revision_date as revision_date,
      mr.number as number,
      t1.description as description
    FROM vulnerability_revision as t1
    RIGHT JOIN max_revision as mr ON t1.revision_date = mr.revision_date and toFloat32(t1.number) = mr.number and t1.vulnerability_fk = mr.vulnerability_fk
  ),
  vlun_notes as (
    select 
    vulnerability_fk,
    arrayDistinct(groupArray(note)) as note
    from vulnerability_notes 
    group by vulnerability_fk
  ),
    vlun_status as (
    select 
    vulnerability_fk,
    status_type,
    arrayDistinct(groupArray(product_id)) as product_id
    from vulnerability_status 
    group by status_type, vulnerability_fk
  ),
    vlun_ss as (
    select 
    vulnerability_fk,
    base_score,
    temporal_score,
    arrayDistinct(groupArray(product_id)) as product_id
    from vulnerability_score_set 
    group by vulnerability_fk, base_score, temporal_score
  )

  SELECT DISTINCT
    now() as timestamp,
    v.doc_xml_date as doc_xml_date,
    v.cve as cve,
    v.title as vul_title,
    v.cwe as cwe,
    v.cwe_text as cwe_text,
    vs.status_type as status_type,
    vs.product_id as status_product_id,
    vn.note as note,
    vt.threats_type as threats_type,
    vt.description as treat_description,
    vss.base_score as base_score,
    vss.temporal_score as temporal_score,
    vss.product_id as product_id,
    vrv.number as rev_number,
    vrv.revision_date as rev_date,
    vrv.description as rev_description,
    vrm.fixed_build as fixed_build,
    vrm.kb as kb,
    di.status as doc_status,
    di.version as doc_version,
    di.revision_history_number as doc_revision_history_number,
    di.revision_history_date as doc_revision_history_date,
    di.revision_history_description as doc_revision_history_description,
    di.initial_relise_date as doc_initial_relise_date,
    di.current_relise_date as doc_current_relise_date,
    di.publisher_type as doc_publisher_type,
    di.document_title as doc_document_title,
    di.contact_details as doc_contact_details,
    di.issuring_authority as doc_issuring_authority,
    di.document_title as doc_title,
    di.document_type as doc_type,
    di.vlun as doc_vlun,
    di.dc as doc_dc,
    di.cvrf_common as doc_cvrf_common,
    di.prod as doc_prod,
    di.scap_core as doc_scap_core,
    di.cvssv2 as doc_cvssv2,
    di.cpe_lang as doc_cpe_lang,
    di.sch as doc_sch,
    di.cvrf as doc_cvrf
FROM vulnerability as v
left join vlun_status as vs on v.id = vs.vulnerability_fk
left join vlun_notes as vn on v.id = vn.vulnerability_fk
left join vuln_threats as vt on v.id = vt.vulnerability_fk
left join vlun_ss  as vss on v.id = vss.vulnerability_fk
left join vuln_revision  as vrv on v.id = vrv.vulnerability_fk
left join vuln_remediation  as vrm on v.id = vrm.vulnerability_fk
left join document_info as di on v.doc_xml_date = di.id;



create materialized view if not exists mv_cve_data to cve_data
    as
WITH
  vuln_remediation as (
    SELECT vulnerability_fk, 
    arrayDistinct(groupArray(kb)) as kb,
    arrayDistinct(groupArray(fixed_build)) as fixed_build 
    FROM vulnerability_remediation 
    GROUP BY vulnerability_fk
  ),
  vuln_threats as (
    SELECT vulnerability_fk, 
    arrayDistinct(groupArray(threats_type)) as threats_type, 
    arrayDistinct(groupArray(description)) as description 
    FROM vulnerability_threats 
    GROUP BY vulnerability_fk
  ),
  max_revision as (
    select
      max(revision_date) as revision_date,
      max(toFloat32(number)) as number,
      vulnerability_fk,
    from vulnerability_revision
    GROUP BY vulnerability_fk
  ),
  vuln_revision as (
    select
      mr.vulnerability_fk as vulnerability_fk,
      mr.revision_date as revision_date,
      mr.number as number,
      t1.description as description
    FROM vulnerability_revision as t1
    RIGHT JOIN max_revision as mr ON t1.revision_date = mr.revision_date and toFloat32(t1.number) = mr.number and t1.vulnerability_fk = mr.vulnerability_fk
  ),
  vlun_notes as (
    select 
    vulnerability_fk,
    arrayDistinct(groupArray(note)) as note
    from vulnerability_notes 
    group by vulnerability_fk
  ),
    vlun_status as (
    select 
    vulnerability_fk,
    status_type,
    arrayDistinct(groupArray(product_id)) as product_id
    from vulnerability_status 
    group by status_type, vulnerability_fk
  ),
    vlun_ss as (
    select 
    vulnerability_fk,
    base_score,
    temporal_score,
    arrayDistinct(groupArray(product_id)) as product_id
    from vulnerability_score_set 
    group by vulnerability_fk, base_score, temporal_score
  )

  SELECT DISTINCT
    now() as timestamp,
    v.doc_xml_date as doc_xml_date,
    v.cve as cve,
    v.title as vul_title,
    v.cwe as cwe,
    v.cwe_text as cwe_text,
    vs.status_type as status_type,
    vs.product_id as status_product_id,
    vn.note as note,
    vt.threats_type as threats_type,
    vt.description as treat_description,
    vss.base_score as base_score,
    vss.temporal_score as temporal_score,
    vss.product_id as product_id,
    vrv.number as rev_number,
    vrv.revision_date as rev_date,
    vrv.description as rev_description,
    vrm.kb as kb,
    vrm.fixed_build as fixed_build,
    di.status as doc_status,
    di.version as doc_version,
    di.revision_history_number as doc_revision_history_number,
    di.revision_history_date as doc_revision_history_date,
    di.revision_history_description as doc_revision_history_description,
    di.initial_relise_date as doc_initial_relise_date,
    di.current_relise_date as doc_current_relise_date,
    di.publisher_type as doc_publisher_type,
    di.document_title as doc_document_title,
    di.contact_details as doc_contact_details,
    di.issuring_authority as doc_issuring_authority,
    di.document_title as doc_title,
    di.document_type as doc_type,
    di.vlun as doc_vlun,
    di.dc as doc_dc,
    di.cvrf_common as doc_cvrf_common,
    di.prod as doc_prod,
    di.scap_core as doc_scap_core,
    di.cvssv2 as doc_cvssv2,
    di.cpe_lang as doc_cpe_lang,
    di.sch as doc_sch,
    di.cvrf as doc_cvrf
FROM vulnerability as v
left join vlun_status as vs on v.id = vs.vulnerability_fk
left join vlun_notes as vn on v.id = vn.vulnerability_fk
left join vuln_threats as vt on v.id = vt.vulnerability_fk
left join vlun_ss  as vss on v.id = vss.vulnerability_fk
left join vuln_revision  as vrv on v.id = vrv.vulnerability_fk
left join vuln_remediation  as vrm on v.id = vrm.vulnerability_fk
left join document_info as di on v.doc_xml_date = di.id

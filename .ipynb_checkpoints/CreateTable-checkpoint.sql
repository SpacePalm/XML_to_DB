DROP TABLE IF EXISTS vulnerability ;
DROP TABLE IF EXISTS vulnerability_status ;
DROP TABLE IF EXISTS vulnerability_notes ;
DROP TABLE IF EXISTS vulnerability_threats ;
DROP TABLE IF EXISTS vulnerability_score_set ;
DROP TABLE IF EXISTS vulnerability_revision ;
DROP TABLE IF EXISTS vulnerability_remediation;
DROP TABLE IF EXISTS product ;
DROP TABLE IF EXISTS document_info ;
DROP TABLE IF EXISTS kb ;

CREATE TABLE vulnerability(

id UInt64,
doc_xml_date Nullable(String),
cve Nullable(String),
title Nullable(String),
cwe Nullable(String),
cwe_text Nullable(String)

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE vulnerability_status(

id UInt64,
vulnerability_fk UInt64,
status_type String,
product_id String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE vulnerability_notes(

id UInt64,
vulnerability_fk UInt64,
title  Nullable(String),
notes_type  Nullable(String),
note  Nullable(String)

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE vulnerability_threats(

id UInt64,
vulnerability_fk UInt64,
title String,
threats_type String,
description String,
product_id String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE vulnerability_score_set(

id UInt64,
vulnerability_fk UInt64,
base_score String,
temporal_score String,
vector String,
product_id String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE vulnerability_revision(

id UInt64,
vulnerability_fk UInt64,
number String,
revision_date DateTime,
description String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE vulnerability_remediation(

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

CREATE TABLE product(

id String,
product_name String,
product_type String

)
ENGINE = MergeTree
ORDER BY id;

CREATE TABLE document_info(

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
ORDER BY id

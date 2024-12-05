# XML_to_DB


class OvalParser:
    def __init__(self, filepath):
        self.ns = {
            'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'common': 'http://oval.mitre.org/XMLSchema/oval-common-5',
            'ios': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#ios',
            'unix': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
            'independent': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
        }
        filename = filepath.split('/')
        if len(filename) > 1:
            filename = filename[1]
        else:
            filename = filename[0]
        filename = filepath.split('\\')
        if len(filename) > 1:
            filename = filename[1]
        else:
            filename = filename[0]
        filename = filename.split('.xml')[0]
        self.xmL = etree.parse(filepath)
        self.root = self.xmL.getroot()
        self.generator = self.root.find('oval:generator', self.ns)
        self.result = []
        self.template = {
            'file_name': filename,
            'oval_product_name': None,
            'oval_product_version': None,
            'oval_schema_version': None,
            'oval_timestamp': None,
            'definition_class': None,
            'definition_id': None,
            'definition_version': None,
            'metadata_title': None,
            'metadata_affected_family': None,
            'metadata_affected_platforms': [],
            'metadata_affected_products': [],
            'metadata_references': [],
            'metadata_description': None,
            'metadata_bdu_cwes': [],
            'metadata_bdu_CVSS2.0_id': None,
            'metadata_bdu_CVSS2.0_score': None,
            'metadata_bdu_CVSS3.0_id': None,
            'metadata_bdu_CVSS3.0_score': None,
            'metadata_bdu_severity': None,
            'metadata_bdu_remediation': None,
            # 'criteria_product_inventories': None,
            'criterions': [],
            'metadata_debian_dsa': None,
            'metadata_debian_date': None,
            'metadata_advisory_source': None,
            'metadata_advisory_severity': None,
            'metadata_advisory_issued_date': None,
            'metadata_advisory_cve': [],
            'metadata_advisory_bug': None,
        }
        

        self.metadata_good_keys = [
            'title',
            'affected',
            'family',
            'platform',
            'product',
            'reference',
            'description',
            'bdu',
            'cwe',
            'CVSS2.0',
            'CVSS3.0',
            'severity',
            'remediation',
            'cvssv20',
            'debian',
            'moreinfo',
            'date',
            'dsa',
            'cve',
            'advisory',
            'issued',
            'bug',
            'ref'
        ]
        # print('Set template')
        self.set_template()
        # print('Get definitions')
        self.get_definitions()

    def set_template(self):
        if type(self.generator) is etree.Element:
            product_name = self.generator.find('common:product_name', self.ns)
            if product_name is not None:
                self.template['oval_product_name'] = product_name.text
            prod_version = self.generator.find('common:product_version', self.ns)
            if prod_version is not None:
                self.template['oval_product_version'] = prod_version.text
            schema_version = self.generator.find('common:schema_version', self.ns)
            if schema_version is not None:
                self.template['oval_schema_version'] = schema_version.text
            timestamp = self.generator.find('common:timestamp', self.ns)
            if timestamp is not None:
                try:
                    self.template['oval_timestamp'] = parser.parse(timestamp.text)
                except:
                    self.template['oval_timestamp'] = None

    @staticmethod
    def get_params(items):
        _params = {}
        if type(items) is list or tuple:
            for x, v in items:
                _params[x] = v

        return _params

    def get_definitions(self):
        for definitions in self.root.findall('oval:definitions', self.ns):
            for definition in definitions.findall('oval:definition', self.ns):
                result = self.template.copy()
                definition_item = self.get_params(definition.items())
                if 'class' in definition_item:
                    definition_item['definition_class'] = definition_item.pop('class')
                    result['definition_class'] = definition_item['definition_class'].strip()
                if 'id' in definition_item:
                    definition_item['definition_id'] = definition_item.pop('id')
                    result['definition_id'] = definition_item['definition_id']
                if 'version' in definition_item:
                    definition_item['definition_version'] = definition_item.pop('version')
                    result['definition_version'] = definition_item['definition_version']
                for key in definition_item.keys():
                    if key not in self.template:
                        print(f'{key} not in template')
                # pprint(result, indent=2)
                result = self.get_definition(definition, result)
                self.result.append(result)
                # pprint(result, indent=2)

    def get_definition(self, definition, result):
        # print('Get metadata')
        result = self.get_metadata(definition, result)
        # print('Get criteria')
        result = self.get_criteria(definition, result)
        return result

    def get_metadata(self, definition, result):
        metadata = definition.find('oval:metadata', self.ns)
        list_metadata_items = [item_name.tag.split('}')[1] for item_name in metadata.iter() if item_name.tag.split('}')[1] != 'metadata']
        for metadata_item in list_metadata_items:
            if metadata_item not in self.metadata_good_keys:
                print(f'{metadata_item} not in metadata_good_keys')
        title = metadata.find('oval:title', self.ns)
        if title is not None:
            result['metadata_title'] = title.text.strip()
        affected = metadata.find('oval:affected', self.ns)
        if affected is not None:
            affected_item = self.get_params(affected.items())
            if 'family' in affected_item:
                result['metadata_affected_family'] = affected_item['family'].strip()
            platforms = [_.text for _ in affected.findall('oval:platform', self.ns)]
            result['metadata_affected_platforms'] = platforms
            products = [_.text for _ in affected.findall('oval:product', self.ns)]
            result['metadata_affected_products'] = products
        references = [self.get_params(reference.items()) for reference in metadata.findall('oval:reference', self.ns)]
        result['metadata_references'] = references


        description = metadata.find('oval:description', self.ns)
        if description is not None:
            result['metadata_description'] = description.text.strip() if description.text else None

        advisory = metadata.find('oval:advisory', self.ns)
        if advisory is not None:
            adv = self.get_params(advisory.items())
            if 'from' in adv:
                adv['metadata_advisory_source'] = adv.pop('from')
                result['metadata_advisory_source'] = adv['metadata_advisory_source']
            
            issued = advisory.find('oval:issued', self.ns)
            if issued is not None:
                issued = self.get_params(issued.items())
                if 'date' in issued:
                    issued['metadata_advisory_issued_date'] = issued.pop('date')
                    result['metadata_advisory_issued_date'] = issued['metadata_advisory_issued_date']

            
            severity = advisory.find('oval:severity', self.ns)
            if severity is not None:
                result['metadata_advisory_severity'] = severity.text.strip()

            cve = [self.get_params(i.items()) for i in advisory.findall('oval:cve', self.ns)]
            
            result['metadata_advisory_cve'] = cve

            bug = advisory.find('oval:bug', self.ns)
            if bug is not None:
                result['metadata_advisory_bug'] = bug.text.strip()

        debian =  metadata.find('oval:debian', self.ns)
        if debian is not None:
            dsa = debian.findall('oval:dsa', self.ns)
            if len(dsa) > 0:
                result['metadata_debian_dsa'] = dsa[0].text.strip()
            date = debian.findall('oval:date', self.ns)
            if len(date) > 0:
                result['metadata_debian_date'] = date[0].text.strip()
            
        bdu = metadata.find('oval:bdu', self.ns)
        if bdu is not None:
            severity = bdu.find('oval:severity', self.ns)
            if severity is not None:
                result['metadata_bdu_severity'] = severity.text.strip()
            remediation = bdu.find('oval:remediation', self.ns)
            if remediation is not None:
                result['metadata_bdu_remediation'] = remediation.text.strip()
            cwes_raw = bdu.findall('oval:cwe', self.ns)
            cwes = []
            for cwe in cwes_raw:
                if cwe.text:
                    parced_cwes = re.findall('[cC][wW][Ee]-\d*', cwe.text)
                    for parced_cwe in parced_cwes:
                        cwes.append(parced_cwe)
            result['metadata_bdu_cwes'] = cwes
            cvss20 = bdu.find('oval:CVSS2.0', self.ns)
            if cvss20 is not None:
                _id = re.findall('AV:[^\']*', cvss20.text)
                score = re.findall('\d*\.\d', cvss20.text)
                if len(_id) > 1:
                    print(f'{_id} id больше 1')
                elif len(_id) == 1:
                    result['metadata_bdu_CVSS2.0_id'] = _id[0]
                if len(score) > 1:
                    print(f'{score} score больше 1')
                elif len(score) == 1:
                    result['metadata_bdu_CVSS2.0_score'] = score[0]
            else:
                cvss20 = bdu.find('oval:cvssv20', self.ns)
                if cvss20 is not None:
                    _id = re.findall('AV:[^\']*', cvss20.text)
                    score = re.findall('\d*\.\d', cvss20.text)
                    if len(_id) > 1:
                        print(f'{_id} id больше 1')
                    elif len(_id) == 1:
                        result['metadata_bdu_CVSS2.0_id'] = _id[0]
                    if len(score) > 1:
                        print(f'{score} score больше 1')
                    elif len(score) == 1:
                        result['metadata_bdu_CVSS2.0_score'] = score[0]
            cvss30 = bdu.find('oval:CVSS3.0', self.ns)
            if cvss30 is not None:
                _id = re.findall('AV:[^\']*', cvss30.text)
                score = re.findall('\d*\.\d', cvss30.text)
                if len(_id) > 1:
                    print(f'{_id} id больше 1')
                elif len(_id) == 1:
                    result['metadata_bdu_CVSS3.0_id'] = _id[0]
                if len(score) > 1:
                    print(f'{score} score больше 1')
                elif len(score) == 1:
                    result['metadata_bdu_CVSS3.0_score'] = score[0]
        return result

    def get_criteria(self, definition, result):
        criteria = definition.find('oval:criteria', self.ns)
        criterions = []
        operator = {
            'is earlier than': '<',
            'is greater than': '>',

        }
        for element in criteria.iter():
            if 'criterion' in element.tag:
                atrib = element.attrib['comment']
                app_name = atrib.split(maxsplit=1)[0]
                version = atrib.rsplit(maxsplit=1)[-1]
                
                good = False
                for key in operator.keys():
                    if key in atrib:
                        
                        good = True
                        version = operator[key] + ' ' + version
                if not good:
                    pass
                if app_name == "Debian":
                    version = atrib.split(maxsplit=2)[1]
                criterions.append({
                    'app_name': app_name,
                    'version': version,
                    'test_ref': element.attrib['test_ref']
                })
                
            result['criterions'] = criterions

               
        return result

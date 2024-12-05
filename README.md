# XML_to_DB


class OvalParser:
    def __init__(self, filepath: str):
        self.ns = {
            'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'common': 'http://oval.mitre.org/XMLSchema/oval-common-5',
            'ios': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#ios',
            'unix': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
            'independent': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
        }

        self.file_name = os.path.splitext(os.path.basename(filepath))[0]
        self.xml_tree = etree.parse(filepath)
        self.root = self.xml_tree.getroot()
        self.generator = self.root.find('oval:generator', self.ns)

        self.template = self.initialize_template()
        self.metadata_good_keys = self.get_metadata_keys()

        self.result = []
        self.set_template()
        self.get_definitions()

    def initialize_template(self) -> Dict[str, Any]:
        """Инициализирует шаблон результата."""
        return {
            'file_name': self.file_name,
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
            'criterions': [],
            'metadata_debian_dsa': None,
            'metadata_debian_date': None,
            'metadata_advisory_source': None,
            'metadata_advisory_severity': None,
            'metadata_advisory_issued_date': None,
            'metadata_advisory_cve': [],
            'metadata_advisory_bug': None,
        }

    @staticmethod
    def get_metadata_keys() -> List[str]:
        """Возвращает список допустимых метаданных."""
        return [
            'title', 'affected', 'family', 'platform', 'product', 'reference',
            'description', 'bdu', 'cwe', 'CVSS2.0', 'CVSS3.0', 'severity',
            'remediation', 'cvssv20', 'debian', 'moreinfo', 'date', 'dsa', 
            'cve', 'advisory', 'issued', 'bug', 'ref'
        ]

    def set_template(self):
        """Устанавливает значения шаблона из генератора."""
        if isinstance(self.generator, etree.Element):
            self.template['oval_product_name'] = self.get_element_text('common:product_name')
            self.template['oval_product_version'] = self.get_element_text('common:product_version')
            self.template['oval_schema_version'] = self.get_element_text('common:schema_version')
            timestamp = self.get_element_text('common:timestamp')
            self.template['oval_timestamp'] = self.parse_timestamp(timestamp)

    def get_element_text(self, tag: str) -> str:
        """Возвращает текст из указанного элемента."""
        element = self.generator.find(tag, self.ns) if self.generator is not None else None
        return element.text.strip() if element is not None else None

    @staticmethod
    def parse_timestamp(timestamp: str) -> Any:
        """Парсит временную метку."""
        try:
            return parser.parse(timestamp) if timestamp else None
        except Exception:
            return None

    def get_definitions(self):
        """Обрабатывает определения из файла."""
        for definitions in self.root.findall('oval:definitions', self.ns):
            for definition in definitions.findall('oval:definition', self.ns):
                result = self.template.copy()
                attributes = dict(definition.items())

                result.update({
                    'definition_class': attributes.get('class'),
                    'definition_id': attributes.get('id'),
                    'definition_version': attributes.get('version'),
                })

                result = self.get_definition(definition, result)
                self.result.append(result)

    def get_definition(self, definition: etree.Element, result: Dict[str, Any]) -> Dict[str, Any]:
        """Обрабатывает метаданные и критерии."""
        result = self.get_metadata(definition, result)
        result = self.get_criteria(definition, result)
        return result

    def get_metadata(self, definition: etree.Element, result: Dict[str, Any]) -> Dict[str, Any]:
        """Извлекает метаданные."""
        metadata = definition.find('oval:metadata', self.ns)
        if metadata is None:
            return result

        result['metadata_title'] = self.get_element_text('oval:title')
        affected = metadata.find('oval:affected', self.ns)
        if affected:
            result['metadata_affected_family'] = affected.get('family', '').strip()
            result['metadata_affected_platforms'] = [
                platform.text for platform in affected.findall('oval:platform', self.ns)
            ]
            result['metadata_affected_products'] = [
                product.text for product in affected.findall('oval:product', self.ns)
            ]
        result['metadata_references'] = [
            dict(reference.items()) for reference in metadata.findall('oval:reference', self.ns)
        ]
        description = metadata.find('oval:description', self.ns)
        result['metadata_description'] = description.text.strip() if description is not None else None

        # Добавить дополнительную обработку advisory, debian и bdu при необходимости.

        return result

    def get_criteria(self, definition: etree.Element, result: Dict[str, Any]) -> Dict[str, Any]:
        """Обрабатывает критерии."""
        criteria = definition.find('oval:criteria', self.ns)
        if criteria is None:
            return result

        criterions = []
        for element in criteria.iter():
            if 'criterion' in element.tag:
                comment = element.attrib.get('comment', '')
                app_name = comment.split(maxsplit=1)[0]
                version = comment.rsplit(maxsplit=1)[-1]
                criterions.append({
                    'app_name': app_name,
                    'version': version,
                    'test_ref': element.attrib.get('test_ref'),
                })
        result['criterions'] = criterions
        return result

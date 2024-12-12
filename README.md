    def run_notebook(self, file_path):
        """Выполняет все ячейки Jupyter Notebook и отображает интерфейс."""
        self.output_area.clear_output()
        with self.output_area:
            try:
                # Читаем файл ноутбука
                with open(file_path, 'r', encoding='utf-8') as f:
                    notebook = nbformat.read(f, as_version=4)
                
                # Создаем процессор для выполнения ноутбука
                ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
                ep.preprocess(notebook, {'metadata': {'path': str(file_path.parent)}})
                
                # Отображаем вывод каждой ячейки
                for cell in notebook.cells:
                    if cell.cell_type == 'code' and 'outputs' in cell:
                        for output in cell.outputs:
                            if 'text' in output:
                                print(output['text'])
                            if 'data' in output:
                                # Если это HTML или виджет, отображаем через display
                                if 'text/html' in output['data']:
                                    display(output['data']['text/html'])
                                elif 'application/vnd.jupyter.widget-view+json' in output['data']:
                                    display(output['data']['application/vnd.jupyter.widget-view+json'])
                                elif 'text/plain' in output['data']:
                                    print(output['data']['text/plain'])
            except Exception as e:
                print(f"Ошибка при выполнении ноутбука {file_path}: {e}")

import nbformat
from nbconvert.preprocessors import ExecutePreprocessor
from pathlib import Path
from ipywidgets import Tab, Output, VBox, Button, HBox
from IPython.display import display


class DynamicInterfacePortal:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.tab = Tab()
        self.folders = {}
        self.output_area = Output()
        self.update_tabs()
        
    def update_tabs(self):
        """Обновляет вкладки на основе папок в директории."""
        subdirs = [d for d in self.base_dir.iterdir() if d.is_dir()]
        for i, folder in enumerate(subdirs):
            if folder not in self.folders:
                self.add_folder_tab(folder, i)
        
        for folder in list(self.folders):
            if folder not in subdirs:
                self.remove_folder_tab(folder)
    
    def add_folder_tab(self, folder, index):
        """Добавляет вкладку для папки."""
        self.folders[folder] = self.create_folder_content(folder)
        self.tab.children = list(self.folders.values())
        self.tab.set_title(index, folder.name)
        
    def remove_folder_tab(self, folder):
        """Удаляет вкладку для папки."""
        del self.folders[folder]
        self.tab.children = list(self.folders.values())
    
    def create_folder_content(self, folder):
        """Создает содержимое вкладки для папки."""
        boxes = []
        items = []
        subb = []
        for file in folder.glob("*.ipynb"):
            btn = Button(description=file.name.replace('.ipynb', ''))
            btn.on_click(lambda _, path=file: self.run_notebook(path))
            items.append(btn)
        subb = [items[i:i + 4] for i in range(0, len(items), 4)]
        for _i in subb:
            boxes.append(VBox(_i))
            
        return HBox(boxes) if boxes else VBox([Output(value=f"No notebooks found in {folder.name}")])
    
    def run_notebook(self, file_path):
        """Выполняет все ячейки Jupyter Notebook и отображает вывод."""
        self.output_area.clear_output()
        with self.output_area:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    notebook = nbformat.read(f, as_version=4)
                
                # Создаем процессор для выполнения ноутбука
                ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
                ep.preprocess(notebook, {'metadata': {'path': str(file_path.parent)}})
                
                # Выводим результат выполнения ячеек с выводом
                for cell in notebook.cells:
                    if cell.cell_type == 'code' and 'outputs' in cell:
                        for output in cell.outputs:
                            if 'text' in output:
                                print(output['text'])
                            if 'data' in output and 'text/plain' in output['data']:
                                print(output['data']['text/plain'])
            except Exception as e:
                print(f"Ошибка при выполнении ноутбука {file_path}: {e}")


def display_portal(base_dir=""):
    """Отображает портал интерфейсов."""
    portal = DynamicInterfacePortal(base_dir)
    display(portal.tab)
    display(portal.output_area)


display_portal("")

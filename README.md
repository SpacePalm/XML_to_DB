import os
import nbformat
from pathlib import Path
from ipywidgets import Tab, VBox, Button, Output
from nbconvert.preprocessors import ExecutePreprocessor
from IPython.display import display, HTML

class DynamicNotebookPortal:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.tab = Tab()
        self.folders = {}
        self.output_area = Output()  # Общая область вывода
        self.update_tabs()
        
    def update_tabs(self):
        """Обновляет вкладки в интерфейсе."""
        subdirs = [d for d in self.base_dir.iterdir() if d.is_dir()]
        for i, folder in enumerate(subdirs):
            if folder not in self.folders:
                # Создаем новую вкладку
                self.add_folder_tab(folder, i)
        
        # Удаляем удаленные папки из интерфейса
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
        """Создает содержимое для вкладки."""
        items = []
        for file in folder.glob("*.ipynb"):
            btn = Button(description=f"Run {file.name}")
            btn.on_click(lambda _, path=file: self.run_notebook(path))
            items.append(btn)
        return VBox(items)
    
    def run_notebook(self, notebook_path):
        """Выполняет Jupyter Notebook и отображает результат."""
        with self.output_area:
            self.output_area.clear_output()  # Очищаем предыдущий вывод
            try:
                # Читаем файл .ipynb
                with open(notebook_path, "r", encoding="utf-8") as f:
                    nb = nbformat.read(f, as_version=4)
                
                # Выполняем блокнот
                ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
                ep.preprocess(nb, {'metadata': {'path': str(notebook_path.parent)}})
                
                # Преобразуем в HTML
                html_content = "".join(cell.get("outputs", "") for cell in nb.cells if "outputs" in cell)
                display(HTML(html_content))
            except Exception as e:
                print(f"Ошибка при выполнении {notebook_path}: {e}")

def display_portal(base_dir=""):
    """Функция для отображения портала."""
    portal = DynamicNotebookPortal(base_dir)
    display(portal.tab)  # Вкладки
    display(portal.output_area)  # Общий вывод

# Вызываем функцию отображения
display_portal("")

import nbformat
from pathlib import Path
from ipywidgets import Tab, VBox, Output
from IPython.display import display
import importlib.util
import sys

class DynamicInterfacePortal:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.tab = Tab()
        self.folders = {}
        self.output_area = Output()  # Для вывода ошибок или отладочной информации
        self.update_tabs()
        
    def update_tabs(self):
        """Обновляет вкладки в интерфейсе."""
        subdirs = [d for d in self.base_dir.iterdir() if d.is_dir()]
        for i, folder in enumerate(subdirs):
            if folder not in self.folders:
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
            interface = self.load_notebook_interface(file)
            if interface:
                items.append(interface)
        return VBox(items) if items else VBox([Output(value=f"No interfaces found in {folder.name}")])
    
    def load_notebook_interface(self, notebook_path):
        """Загружает интерфейс из Jupyter Notebook."""
        with self.output_area:
            try:
                # Открываем .ipynb файл и исполняем код
                with open(notebook_path, "r", encoding="utf-8") as f:
                    notebook = nbformat.read(f, as_version=4)
                
                # Выполняем код ячеек
                local_env = {}
                for cell in notebook.cells:
                    if cell.cell_type == "code":
                        exec(cell.source, globals(), local_env)
                
                # Ожидаем функцию create_interface
                if "create_interface" in local_env:
                    return local_env["create_interface"]()
                else:
                    print(f"Функция create_interface не найдена в {notebook_path}")
                    return None
            except Exception as e:
                print(f"Ошибка при загрузке интерфейса из {notebook_path}: {e}")
                return None

def display_portal(base_dir=""):
    """Функция для отображения портала."""
    portal = DynamicInterfacePortal(base_dir)
    display(portal.tab)  # Вкладки
    display(portal.output_area)  # Общий вывод

# Вызываем функцию отображения
display_portal("path/to/your/folder")

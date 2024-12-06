import importlib.util
from pathlib import Path
from ipywidgets import Tab, Output, VBox
from IPython.display import display

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
            # Попытка загрузить интерфейс из файла
            interface = self.load_interface(file)
            if interface:
                items.append(interface)
        return VBox(items) if items else VBox([Output(value=f"No interfaces found in {folder.name}")])
    
    def load_interface(self, file_path):
        """Загружает интерфейс из файла как модуль."""
        with self.output_area:
            try:
                spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                # Ожидается, что в модуле будет функция create_interface()
                return module.create_interface()
            except Exception as e:
                print(f"Ошибка при загрузке интерфейса из {file_path}: {e}")
                return None

def display_portal(base_dir=""):
    """Функция для отображения портала."""
    portal = DynamicInterfacePortal(base_dir)
    display(portal.tab)  # Вкладки
    display(portal.output_area)  # Общий вывод

# Вызываем функцию отображения
display_portal("path/to/your/folder")

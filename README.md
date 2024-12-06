import os
from pathlib import Path
from ipywidgets import Tab, VBox, Button, Output, IFrame
from IPython.display import display

class DynamicNotebookPortal:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.tab = Tab()
        self.folders = {}
        self.output_area = Output()  # Общая область вывода для отладки или сообщений
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
            btn = Button(description=f"Open {file.name}")
            btn.on_click(lambda _, path=file: self.display_notebook_in_iframe(path))
            items.append(btn)
        return VBox(items)
    
    def display_notebook_in_iframe(self, notebook_path):
        """Отображает Jupyter Notebook в IFrame."""
        with self.output_area:
            self.output_area.clear_output()
            try:
                # Формируем URL для блокнота
                relative_path = notebook_path.relative_to(self.base_dir)
                iframe_url = f"/notebooks/{relative_path}"  # Убедитесь, что сервер Jupyter позволяет доступ к файлам
                iframe = IFrame(src=iframe_url, width="100%", height="600px")
                display(iframe)
            except Exception as e:
                print(f"Ошибка при отображении {notebook_path}: {e}")
    
def display_portal(base_dir=""):
    """Функция для отображения портала."""
    portal = DynamicNotebookPortal(base_dir)
    display(portal.tab)  # Вкладки
    display(portal.output_area)  # Общий вывод

# Вызываем функцию отображения
display_portal("path/to/your/folder")

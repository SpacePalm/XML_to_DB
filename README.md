import importlib.util
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
        
        subdirs = [d for d in self.base_dir.iterdir() if d.is_dir()]
        for i, folder in enumerate(subdirs):
            if folder not in self.folders:
                self.add_folder_tab(folder, i)
        
        
        for folder in list(self.folders):
            if folder not in subdirs:
                self.remove_folder_tab(folder)
    
    def add_folder_tab(self, folder, index):
        
        self.folders[folder] = self.create_folder_content(folder)
        self.tab.children = list(self.folders.values())
        self.tab.set_title(index, folder.name)
        
    def remove_folder_tab(self, folder):
        """Удаляет вкладку для папки."""
        del self.folders[folder]
        self.tab.children = list(self.folders.values())
    
    def create_folder_content(self, folder):
        boxes = []
        items = []
        subb = []
        for file in folder.glob("*.py"):
            
            btn = Button(description = file.name.replace('.py', ''))
            btn.on_click(lambda _, path = file: self.load_interface(path))
            interface = self.load_interface(file)
            items.append(btn)
            if interface:
                items.append(btn)
        subb = [items[_:_ + 4] for _ in range(0, len(items), 4)]
        for _i in subb:
            boxes.append(VBox(_i))
            
        return HBox(boxes) if boxes else VBox([Output(value=f"No interfaces found in {folder.name}")])
    
    def load_interface(self, file_path):
        
        self.output_area.clear_output()
        with self.output_area:
            # %run 
            try:
                spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                # Ожидается, что в модуле будет функция create_interface()
                return display(module.create_interface())
            except Exception as e:
                print(f"Ошибка при загрузке интерфейса из {file_path}: {e}")
                return None

def display_portal(base_dir=""):
    
    portal = DynamicInterfacePortal(base_dir)
    display(portal.tab)  
    display(portal.output_area) 


display_portal("notebooks")

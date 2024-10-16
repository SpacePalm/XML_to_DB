import requests

# URL с XML данными
url = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2023-May'

# Получаем данные по ссылке
response = requests.get(url)

# Проверка успешности запроса
if response.status_code == 200:
    # Записываем содержимое XML в файл
    with open('data.xml', 'wb') as file:
        file.write(response.content)
else:
    print("Не удалось получить данные, статус код:", response.status_code)
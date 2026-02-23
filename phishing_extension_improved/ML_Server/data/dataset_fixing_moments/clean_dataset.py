import pandas as pd
import os

# Загрузка датасета
input_path = os.path.join('data', 'malicious_phish.csv')
output_path = os.path.join('data', 'malicious_phish_cleaned.csv')

print("Загрузка датасета...")
df = pd.read_csv(input_path)

# Вывод информации до очистки
print("\nИнформация до очистки:")
print(f"Размер датасета: {len(df)}")
print("\nПропущенные значения:")
print(df.isnull().sum())

# Находим строку с пропущенным значением
missing_row = df[df['url'].isnull()]
if not missing_row.empty:
    print("\nНайдена строка с пропущенным URL:")
    print(missing_row)
    
    # Удаляем строку с пропущенным значением
    df = df.dropna(subset=['url'])
    
    # Сохраняем очищенный датасет
    df.to_csv(output_path, index=False)
    
    # Вывод информации после очистки
    print("\nИнформация после очистки:")
    print(f"Размер датасета: {len(df)}")
    print("\nПропущенные значения:")
    print(df.isnull().sum())
    print(f"\nОчищенный датасет сохранен в: {output_path}")
else:
    print("\nПропущенных значений не найдено") 
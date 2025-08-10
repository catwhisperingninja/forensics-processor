import pandas as pd
import numpy as np
from datetime import datetime

# Create some test data
data = {
    'Name': ['John', 'Jane', 'Bob', 'Alice'],
    'Age': [28, 34, 42, 31],
    'Department': ['Engineering', 'HR', 'Marketing', 'Finance'],
    'Salary': [75000, 85000, 62000, 79000]
}

# Create a DataFrame
df = pd.DataFrame(data)

# Create a simple Excel file with pandas
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f'test_excel_{timestamp}.xlsx'

try:
    # Use the openpyxl engine
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Employees', index=False)

        # Create a second sheet with different data
        df2 = pd.DataFrame(np.random.randn(10, 4), columns=['A', 'B', 'C', 'D'])
        df2.to_excel(writer, sheet_name='Random Data', index=False)

    print(f"Excel file created successfully: {output_file}")

    # Verify the file can be read back
    read_df = pd.read_excel(output_file, sheet_name='Employees')
    print("\nData read back successfully:")
    print(read_df.head())

    # Show available sheets
    xl = pd.ExcelFile(output_file)
    print(f"\nSheets in the workbook: {xl.sheet_names}")

except Exception as e:
    print(f"Error creating or reading Excel file: {str(e)}")
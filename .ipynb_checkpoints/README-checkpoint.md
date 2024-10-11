# XML_to_DB


---------------------------------------------------------------------------
TypeError                                 Traceback (most recent call last)
File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/datatypes/string.py:29, in String._data_size(self, sample)
     28                 try:
---> 29                     total += len(x)
     30                 except:
     31 #                    print(sample)
     32 #                    print(x)

TypeError: object of type 'float' has no len()

During handling of the above exception, another exception occurred:

TypeError                                 Traceback (most recent call last)
Cell In[8], line 1
----> 1 connection.insert_df('kb', kb_lake, column_names = ['release_date', 'kb', 'build_number', 'cve', 'doc_xml_date', 'id'])

File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/driver/client.py:585, in Client.insert_df(self, table, df, database, settings, column_names, column_types, column_type_names, context)
    583     elif len(column_names) != len(df.columns):
    584         raise ProgrammingError('DataFrame column count does not match insert_columns') from None
--> 585 return self.insert(table,
    586                    df,
    587                    column_names,
    588                    database,
    589                    column_types=column_types,
    590                    column_type_names=column_type_names,
    591                    settings=settings, context=context)

File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/driver/client.py:553, in Client.insert(self, table, data, column_names, database, column_types, column_type_names, column_oriented, settings, context)
    551     if not context.empty:
    552         raise ProgrammingError('Attempting to insert new data with non-empty insert context') from None
--> 553     context.data = data
    554 return self.data_insert(context)

File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/driver/insert.py:96, in InsertContext.data(self, data)
     94     raise ProgrammingError('Insert data column count does not match column names')
     95 self._data = data
---> 96 self.block_size = self._calc_block_size()

File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/driver/insert.py:114, in InsertContext._calc_block_size(self)
    112     else:
    113         sample = [col_data[j] for j in range(0, self.row_count, sample_freq)]
--> 114         d_size = d_type.data_size(sample)
    115 else:
    116     data = self._data

File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/datatypes/base.py:102, in ClickHouseType.data_size(self, sample)
    100     d_size = self._data_size(values) + 2
    101 else:
--> 102     d_size = self._data_size(sample)
    103 if self.nullable:
    104     d_size += 1

File /usr/local/lib/python3.10/dist-packages/clickhouse_connect/datatypes/string.py:33, in String._data_size(self, sample)
     29                     total += len(x)
     30                 except:
     31 #                    print(sample)
     32 #                    print(x)
---> 33                     total += len(x)
     34         return total // len(sample) + 1

TypeError: object of type 'float' has no len()
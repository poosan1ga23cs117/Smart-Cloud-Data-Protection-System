from s3_manager import s3, BUCKET

response = s3.list_objects_v2(Bucket=BUCKET)

print("Connected successfully!")
print(response)
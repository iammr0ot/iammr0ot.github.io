---
title: Candy Vault - HTB Writeup
date: 2024-04-24 10:03
categories: [ctf, web, easy]
tags: [htb, web, ctf,easy]    # TAG names should be lowercase
---

## CHALLENGE DESCRIPTION

The malevolent spirits have concealed all the Halloween treats within their secret vault, and it's imperative that you decipher its enigmatic seal to reclaim the candy before the spooky night arrives.

## Testing

There is simple login page is running on the server. 

![Pasted image 20240424230519](https://github.com/auk0x01/auk0x01.github.io/assets/74102381/c17582d6-6753-4afd-b6e5-7e2d1421f5bd)

Let's move to the source code of the application. In docker file we discover that their is a **mongodb** running on the background. 
MongoDB is NoSQL, **non-relational document database that provides support for JSON-like storage**. The MongoDB database has a flexible data model that enables you to store unstructured data, and it provides full indexing support, and replication with rich and intuitive APIs.
Great, now we have information about the database running on the backend.

```python
RUN mkdir -p /data/db
# Set permissions for the MongoDB data directory
RUN chown -R mongodb:mongodb /data/db
# Set environment variables for MongoDB
ENV MONGO_URI mongodb://127.0.0.1:27017/candyvault
```

In **app.py** , there is a function called **login**, which checks the **content-type** if it is **json** or **x-www-form-urlencoded** to deal with the input data. 
 
```python
def login():
    content_type = request.headers.get("Content-Type")
   if content_type == "application/x-www-form-urlencoded":
        email = request.form.get("email")
        password = request.form.get("password")
    elif content_type == "application/json":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
    else:
        return jsonify({"error": "Unsupported Content-Type"}), 400
```

After checking the content-type, there is a variable called  **user** which is getting direct input from user, without any validation as a query to match the user's provided input with the database to authenticate the user.

```python
user = users_collection.find_one({"email": email, "password": password})
    if user:
        return render_template("candy.html", flag=open("flag.txt").read())
    else:
        return redirect("/")
```

This piece of code is vulnerable to **NoSQL injection**. 
NoSQL injection is **a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database**. You can learn more about it [here](https://medium.com/@aswinchandran274/nosql-unveiled-vulnerabilities-injection-d5505e0f1db3).
Commonly used operators in NoSQL Injection Vulnerability
- **$ne** = Not equal to
- **$eq** = Equal to
- **$gt** = Greater than
- **$lt** = Less than
- **$regex** = Regular expression
- **$in** = Check if the required data is present in a data structure such as an array

### Exploitation

Let's exploit this vulnerability for login bypass. Firstly intercept the request in the burpsuite. 

![Pasted image 20240424233202](https://github.com/iammR0OT/HTB-Challenges/assets/74102381/b3e05579-05ac-491b-acf8-caf8e8a49e6a)

We will be using **$ne** to bypass login page. Let's create payload

```json
{
	"email": {"$ne": ""},
	"password": {"$ne": ""}
}

```

Now change the content type to **json** and paste our payload in the body of the request. after forwarding the request, we can see that we successfully bypass login page and our flag is present on the home scree.

![Pasted image 20240424233906](https://github.com/iammR0OT/HTB-Challenges/assets/74102381/3fd6146a-36db-45a0-9e8c-d503a6b8a2a6)

That's all for this challenge. Will meet in next writeup

# Happy Hacking ❤

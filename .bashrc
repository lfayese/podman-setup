#!/bin/bash

#======================================================================
# Core Environment Settings & Performance Improvements
#======================================================================
#export LANG="en_US.UTF-8"
#export LC_ALL="en_US.UTF-8"
#export LC_CTYPE="C"
export TERM="xterm-color"

export EDITOR="code"
export VISUAL="nano"

export HISTFILESIZE=10000
export HISTSIZE=500
export HISTCONTROL="ignoredups:ignorespace:erasedups"
shopt -s histappend checkwinsize
set -o noclobber
stty -ixon

PROMPT_COMMAND='history -a; __setprompt'

#======================================================================
# Colors
#======================================================================
BLACK="\[\033[0;30m\]"; BLACKB="\[\033[1;30m\]"
RED="\[\033[0;31m\]"; REDB="\[\033[1;31m\]"
GREEN="\[\033[0;32m\]"; GREENB="\[\033[1;32m\]"
YELLOW="\[\033[0;33m\]"; YELLOWB="\[\033[1;33m\]"
BLUE="\[\033[0;34m\]"; BLUEB="\[\033[1;34m\]"
PURPLE="\[\033[0;35m\]"; PURPLEB="\[\033[1;35m\]"
CYAN="\[\033[0;36m\]"; CYANB="\[\033[1;36m\]"
WHITE="\[\033[0;37m\]"; WHITEB="\[\033[1;37m\]"
RESET="\[\033[0;0m\]"

#======================================================================
# PATH Setup
#======================================================================
export PATH="$PATH:/usr/local/opt/php@7.1/bin:/usr/local/opt/php@7.1/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/share:/mnt/c/Users/639016"
for i in /home/user/*; do [ -d "$i" ] && PATH="$PATH:$i"; done

export JOBS="max"
ulimit -n 10240
export CLICOLOR=1
export LSCOLORS="GxExBxBxFxegedabagacad"

#======================================================================
# Prompt Function
#======================================================================
__setprompt() {
    local LAST_COMMAND=$?
    PS1=""
    if [[ $LAST_COMMAND != 0 ]]; then
        PS1+="\[${BLACKB}\](\[${REDB}\]ERROR\[${BLACKB}\])-(\[${RED}\]Exit Code \[${REDB}\]${LAST_COMMAND}\[${BLACKB}\])-("
        case $LAST_COMMAND in
            1) PS1+="General error" ;;
            2) PS1+="Permission or syntax issue" ;;
            126) PS1+="Not executable" ;;
            127) PS1+="Command not found" ;;
            *) PS1+="Unknown error" ;;
        esac
        PS1+="\[${BLACKB}\])\[${RESET}\]\n"
    fi
    local datetime=$(date '+%b-%d %I:%M%p')
    PS1+="\[${BLACKB}\](\[${CYAN}\]${datetime% *} \[${BLUE}\]${datetime#* }\[${BLACKB}\])-\n"
    PS1+="\[\033[1;35m\]\u@\h \[\033[1;32m\]in \[\033[1;36m\]\W\n"
    if [[ $EUID -ne 0 ]]; then
        PS1+="\[${GREEN}\]>\[${RESET}\] "
    else
        PS1+="\[${RED}\]>\[${RESET}\] "
    fi
}

#======================================================================
# Podman Shortcuts
#======================================================================
alias podup='podman machine start'
alias poddown='podman machine stop'
alias podstat='podman machine list'
alias podls='podman ps -a'
alias podimg='podman images'
alias podrmall='podman rm -a -f'
alias podrmi='podman rmi -a -f'
alias podsh='podman run -it --rm --network=host'
alias podlogs='podman logs -f'
alias podtop='podman stats --no-stream'

# Disabled to prevent errors with non-existent machines
# ensure_podman_running() {
#     if ! podman machine info &>/dev/null; then
#         echo "Starting podman-machine-default..."
#         podman machine start
#     fi
# }

#======================================================================
# Useful Aliases & Functions
#======================================================================
alias ..='cd ..'; alias ...='cd ../..'; alias ....='cd ../../..'
alias home='cd ~'; alias cl='cd "$@" && ll'; alias cs='cd "$@" && ls'
alias ls='ls -aFh --color=always'; alias ll='ls -alh'; alias la='ls -Alh'
alias lt='ls -ltrh'; alias lr='ls -lRh'; alias cp='cp -i'; alias mv='mv -i'
alias rm='rm -iv'; alias mkdir='mkdir -pv'; alias tree="find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'"
alias perm="stat -f '%Lp'"; alias resource='source ~/.bashrc'
alias getsshkey="pbcopy < ~/.ssh/id_rsa.pub"

# Archive extraction
extract() {
    for archive in "$@"; do
        [[ ! -f "$archive" ]] && echo "'$archive' is not a file!" && continue
        case "$archive" in
            *.tar.bz2|*.tbz2) tar xvjf "$archive" ;;
            *.tar.gz|*.tgz) tar xvzf "$archive" ;;
            *.bz2) bunzip2 "$archive" ;;
            *.rar) rar x "$archive" ;;
            *.gz) gunzip "$archive" ;;
            *.tar) tar xvf "$archive" ;;
            *.zip) unzip "$archive" ;;
            *.7z) 7z x "$archive" ;;
            *) echo "Don't know how to extract '$archive'" ;;
        esac
    done
}

# Git log
git-log() {
    git log --pretty="%C(Yellow)%h %C(reset)%ad (%C(Green)%cr%C(reset)) %C(Cyan)%an: %C(reset)%s"
}

# Grep helper
ftext() {
    grep -iIHrn --color=always "$1" . | less
}

# --- SSH Agent Setup for WSL2 ---
env_file="$HOME/.ssh/agent.env"

agent_load_env() {
    [[ -f "$env_file" ]] && source "$env_file" > /dev/null
}

agent_start() {
    echo "Starting new ssh-agent..."
    # Make sure the .ssh directory exists with proper permissions
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    
    # Ensure the file is writable or remove it
    if [[ -f "$env_file" ]]; then
        rm -f "$env_file" 2>/dev/null || chmod +w "$env_file"
    fi
    
    # Kill any existing ssh-agent processes for this user
    pkill -u "$USER" ssh-agent 2>/dev/null
    
    # Start a new agent and write to the environment file
    (umask 077; ssh-agent > "$env_file")
    source "$env_file" > /dev/null
}

agent_load_env

# Check if the socket is valid and agent is running
if [[ ! -S "$SSH_AUTH_SOCK" ]]; then
    agent_start
fi

# Add keys if none are loaded
if ! ssh-add -l &>/dev/null; then
    ssh-add
fi


# Python wrapper
PYTHON_BIN=$(command -v python 2>/dev/null)
python() {
    if [[ -n "$PYTHON_BIN" ]]; then
        winpty "$PYTHON_BIN" "$@"
    else
        echo "Python not found" >&2
        return 1
    fi
}

# Misc functions
cleardir() {
    read -ep 'Clear current directory? [y/N] ' response
    [[ "$response" =~ ^[Yy]$ ]] && rm -rfv -- ./* .[!.]* .??*
}

mktar() { tar cvzf "${1%%/}.tar.gz" "${1%%/}/"; }
mkzip() { zip -r "${1%%/}.zip" "$1"; }
disk-usage() { du -hs "$@" | sort -hr; }
dirdiff() { diff -u <(ls "$1" | sort) <(ls "$2" | sort); }

startserver() {
    local path="$1"; [ -z "$path" ] && path="."
    open http://localhost:3000
    php -t "$path" -S localhost:3000
}

weather() {
    local location="$1"; [ -z "$location" ] && location="dsm"
    curl "http://wttr.in/${location}?lang=en"
}

gitio() {
    [[ -z "$1" || -z "$2" ]] && { echo "Usage: gitio <URL> <code>"; return 1; }
    curl -i https://git.io -F "url=$1" -F "code=$2"
    echo
}

dl-website() {
    local polite=""
    [[ $* == *--polite* ]] && polite="--wait=2 --limit-rate=50K"
    wget --recursive --page-requisites --convert-links --user-agent="Mozilla" $polite "$1"
}

_getsshkey_complete() {
    local cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=( $(compgen -W "$(ls "$HOME/.ssh/")" -- "$cur") )
}
complete -o nospace -F _getsshkey_complete getsshkey

# Extra paths
export PATH="$PATH:/mnt/c/Program Files/Microsoft VS Code/bin"
export PATH="$PATH:/mnt/C/Users/639016/AppData/Local/Programs/Microsoft VS Code/bin"

# Global Variables & GitHub token
export GITHUB_TOKEN='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'

export PATH="$PATH:/usr/local/bin"
alias podman='podman-remote-static-linux_amd64'



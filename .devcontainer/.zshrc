export LANGUAGE=C
export LANG=C
export LC_ALL=C

export ZPLUG_HOME=~/.zplug
source ~/.zplug/init.zsh

# Supports oh-my-zsh plugins and the like
zplug "plugins/git", from:oh-my-zsh
zplug "plugins/docker", from:oh-my-zsh
zplug "plugins/gitignore", from:oh-my-zsh
zplug "plugins/httpie", from:oh-my-zsh
zplug "plugins/linux", from:oh-my-zsh
zplug "plugins/pip", from:oh-my-zsh
zplug "plugins/python", from:oh-my-zsh
zplug "plugins/sudo", from:oh-my-zsh

# Only macOS
zplug "lib/clipboard", from:oh-my-zsh, if:"[[ $OSTYPE == *darwin* ]]"
zplug "plugins/macos", from:oh-my-zsh, if:"[[ $OSTYPE == *darwin* ]]"

# Only Linux
zplug "plugins/linux", from:oh-my-zsh, if:"[[ $OSTYPE == *linux* ]]"

zplug "zsh-users/zsh-autosuggestions", defer:2
zplug "zsh-users/zsh-syntax-highlighting", defer:2
zplug "zsh-users/zsh-completions", defer:2
zplug "MichaelAquilina/zsh-autoswitch-virtualenv", defer:2

zplug mafredri/zsh-async, from:github
zplug sindresorhus/pure, use:pure.zsh, from:github, as:theme

# Install plugins if there are plugins that have not been installed
if ! zplug check; then
    printf "Install? [y/N]: "
    if read -q; then
        echo; zplug install
    fi
fi

# Then, source plugins and add commands to $PATH
zplug load

# Menu-style completion
zstyle ':completion:*' menu select
zstyle ':completion:*' file-sort modification # Youngest files first
zstyle ':completion:*' group-name ''
zstyle ':completion:*:*:*:*:descriptions' format '%F{green}-- %d --%f'

source /root/google-cloud-sdk/path.zsh.inc
source /root/google-cloud-sdk/completion.zsh.inc

# History
HISTFILE=~/.zsh_history
HISTSIZE=10000
SAVEHIST=1000

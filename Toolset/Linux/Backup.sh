#!/bin/bash
#
#
# Bash Backup script for CCDC Team Linux Environments
# Version 3.0.1
# Written by Daniel Barr
#
# ---------------------------------------------------------------------
# Free to use by all teams. Please realize you are using this script
# at your own risk. The author holds no liability and will not be held
# responsible for any damages done to systems or system configurations.
# ---------------------------------------------------------------------
# This script should be used on any Linux system for backing up important
# or valuable directories that could be used to quickly restore a service
# as necessary.
# ---------------------------------------------------------------------
# The goal of this script is to efficiently compress the user specified
# directory into a tar.gz folder. The compressed directory is then uploaded
# to the appropriate git repository.
#
# -------------------------------
# -      Global  Variables      -
# -------------------------------

TIME=$(date +%F-%T)
read -rp "What directory would you like to backup? " -a SRCDIR
DESDIR=~/backups
LOCALGITREPO=$DESDIR/$(hostname)-$(date +%m%d%Y%M%S)
TARFILE="*.tar.gz"

# -------------------------------
# -          Functions          -
# -------------------------------

check_dir(){
        if [ -d "$DESDIR" ]
        then
                echo "[*] Checking if backup directory exists"
                echo "[*] Directory Exists!"
                mkdir "$LOCALGITREPO"
                return 0
        elif [ ! -d "$DESDIR" ]
        then
                echo "[*] Checking if backup directory exists"
                echo
                echo "[!] Directory does not exist!"
                echo
                echo "[*] Creating backup directory"
                echo
                mkdir "$DESDIR"
                mkdir "$LOCALGITREPO"
                echo "[*] Directory Created."
        fi
}

create_tar(){
        for FILENAME in "${SRCDIR[@]}"  # For every line in FILES
        do # Do the following, starting with the first one:
                #echo $FILENAME
                tar -cpzf "$DESDIR/$FILENAME.$TIME.tar.gz" "$FILENAME"
                mv $DESDIR/$TARFILE "$LOCALGITREPO"
        done
}

git_clone(){
    cd $DESDIR
    git init
    git config user.name "pacecybersetters"
    git config user.email "paceccdcteam@gmail.com"
    git remote add origin https://github.com/pacecybersetters/DirigoCyberBackups.git    
    git pull origin master
    git add "$DESDIR"
    git commit -m "Updated backups for $(hostname)"
    git push origin master
}

# Main body of script starts here

check_dir
create_tar
git_clone
#
# Exit with an explicit status code
exit 0

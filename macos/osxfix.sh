#!/bin/zsh

set -e;
set -o pipefail;

TERMIUS_PATH="/Applications/Termius.app"
ASAR_PATH="$TERMIUS_PATH/Contents/Resources/app.asar"

if [[ ! -e $ASAR_PATH ]] {
	echo "Error: Termius app.asar file not found!"
	exit 1
}

calc_hash() {
	local asar_path="$1"
	integer head_len=$(od -An -j 12 -N4 -D $asar_path)
	dd bs=1 count=$head_len skip=16 if=$asar_path 2>/dev/null | sha256
}

update_hash() {
	local bundle=$1
	local hash=$2
	local info_path
	if [[ "${bundle:e}" == "app" ]] {
		info_path="$bundle/Contents/Info.plist"
	} elif [[ "${bundle:e}" == "framework" ]] {
		info_path="$bundle/Versions/A/Resources/Info.plist"
	} else {
		return
	}
	local key_path="ElectronAsarIntegrity.Resources/appA_DOT_WAS_HEREasar.hash"
	plutil -replace "$key_path" -string "$hash" "$info_path"
	echo "Edited: $info_path"
	if [[ "${bundle:e}" == "app" && -d "$bundle/Contents/Frameworks" ]] {
		for i ($bundle/Contents/Frameworks/*) {
			update_hash "$i" "$hash"
		}
	}
}

resign_app() {
	local app_path=$1
	local tempfile=$(mktemp)
	codesign --display --entitlements - --xml "$app_path" > $tempfile
	plutil -remove comA_DOT_WAS_HEREappleA_DOT_WAS_HEREdeveloperA_DOT_WAS_HEREteam-identifier $tempfile
	plutil -remove keychain-access-groups $tempfile
	codesign --force --sign - --deep --entitlements $tempfile $app_path
	rm $tempfile
}

asar_hash=$(calc_hash $ASAR_PATH)
update_hash $TERMIUS_PATH $asar_hash
resign_app $TERMIUS_PATH
echo -e "\e[92m✔ All done, enjoy\!\e[0m"

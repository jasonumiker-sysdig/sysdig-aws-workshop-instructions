#!/bin/bash
# PDX
git branch PDX
git checkout PDX
sed -i -e "s/\*\*Sydney\*\*/\*\*Oregon\*\*/g" Readme.md
sed -i -e "s/\*\*AWS-AP-Sydney\*\*/\*\*US-West\*\*/g" Readme.md
sed -i -e "s|https://app.au1.sysdig.com|https://us2.app.sysdig.com|g" Readme.md
sed -i -e "s|region.png|region-pdx.png|g" Readme.md
sed -i -e "s|sysdiglogin.png|sysdiglogin-pdx.png|g" Readme.md
rm ./Readme.md-e
git add ./Readme.md
git commit -m "PDX Branch"
git push --set-upstream origin PDX
git checkout main
sleep 10
# SFO
git branch SFO
git checkout SFO
sed -i -e "s/\*\*Sydney\*\*/\*\*N. California\*\*/g" Readme.md
sed -i -e "s/\*\*AWS-AP-Sydney\*\*/\*\*GCP-US-West\*\*/g" Readme.md
sed -i -e "s|https://app.au1.sysdig.com|https://app.us4.sysdig.com|g" Readme.md
sed -i -e "s|region.png|region-sfo.png|g" Readme.md
sed -i -e "s|sysdiglogin.png|sysdiglogin-sfo.png|g" Readme.md
rm ./Readme.md-e
git add ./Readme.md
git commit -m "SFO Branch"
git push --set-upstream origin SFO
git checkout main
sleep 10
# FRA
git branch FRA
git checkout FRA
sed -i -e "s/\*\*Sydney\*\*/\*\*Frankfurt\*\*/g" Readme.md
sed -i -e "s/\*\*AWS-AP-Sydney\*\*/\*\*EU-Central\*\*/g" Readme.md
sed -i -e "s|https://app.au1.sysdig.com|https://eu1.app.sysdig.com|g" Readme.md
sed -i -e "s|region.png|region-fra.png|g" Readme.md
sed -i -e "s|sysdiglogin.png|sysdiglogin-fra.png|g" Readme.md
rm ./Readme.md-e
git add ./Readme.md
git commit -m "FRA Branch"
git push --set-upstream origin FRA
git checkout main
sleep 10
# CDG
git branch CDG
git checkout CDG
sed -i -e "s/\*\*Sydney\*\*/\*\*Paris\*\*/g" Readme.md
sed -i -e "s/\*\*AWS-AP-Sydney\*\*/\*\*EU-Central\*\*/g" Readme.md
sed -i -e "s|https://app.au1.sysdig.com|https://eu1.app.sysdig.com|g" Readme.md
sed -i -e "s|region.png|region-cdg.png|g" Readme.md
sed -i -e "s|sysdiglogin.png|sysdiglogin-cdg.png|g" Readme.md
rm ./Readme.md-e
git add ./Readme.md
git commit -m "CDG Branch"
git push --set-upstream origin CDG
git checkout main

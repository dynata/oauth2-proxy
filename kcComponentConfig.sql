select cc.name, replace(replace(cc.value, '-', '+'), '_','/') as value
from keycloak.`COMPONENT_CONFIG` cc
where component_id in
  (
    select c.id
    from keycloak.`COMPONENT` c
    where c.realm_id = (select id from keycloak.`REALM` where name = 'pe')
      and ( c.name = 'rsa-generated' or c.name = 'hmac-generated' )
      and c.PROVIDER_TYPE = 'org.keycloak.keys.KeyProvider'
  )
  and name in ('secret','privateKey') order by 1 desc;
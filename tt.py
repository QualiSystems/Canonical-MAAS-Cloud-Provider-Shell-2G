from maas.client import login


client = login(
    "http://192.168.26.24:5240/MAAS/",
    username="admin", password="admin",
)



# todo: Deploy
# 0. Create resorce to parse the context
# 1. Choose free machine from the pool (by given settings (cores, RAm, disks, storage) )
#   a. If no such machine - raise an Exception
# 2. Get needed OS from the Deployed App "Operation System" field
# 3. Triger "deploy" method. Check in loop while status is not OK
# 4. Implement Power On/Power Off commands

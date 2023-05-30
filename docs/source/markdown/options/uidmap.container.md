####> This option file is used in:
####>   podman create, run
####> If file is edited, make sure the changes
####> are applicable to all of those.
#### **--uidmap**=*container_uid:from_uid:amount*

Run the container in a new user namespace using the supplied UID mapping. This
option conflicts with the **--userns** and **--subuidname** options. This
option provides a way to map host UIDs to container UIDs. It can be passed
several times to map different ranges.

The _from_uid_ value is based upon the user running the command, either rootful or rootless users.
* rootful user:  *container_uid*:*host_uid*:*amount*
* rootless user: *container_uid*:*intermediate_uid*:*amount*

When **podman <<subcommand>>** is called by a privileged user, the option **--uidmap**
works as a direct mapping between host UIDs and container UIDs.

host UID -> container UID

The _amount_ specifies the number of consecutive UIDs that is mapped.
If for example _amount_ is **4** the mapping looks like:

|   host UID     |    container UID    |
| -              | -                   |
| _from_uid_     | _container_uid_     |
| _from_uid_ + 1 | _container_uid_ + 1 |
| _from_uid_ + 2 | _container_uid_ + 2 |
| _from_uid_ + 3 | _container_uid_ + 3 |

When **podman <<subcommand>>** is called by an unprivileged user (i.e. running rootless),
the value _from_uid_ is interpreted as an "intermediate UID". In the rootless
case, host UIDs are not mapped directly to container UIDs. Instead the mapping
happens over two mapping steps:

host UID -> intermediate UID -> container UID

The **--uidmap** option only influences the second mapping step.

The first mapping step is derived by Podman from the contents of the file
_/etc/subuid_ and the UID of the user calling Podman.

First mapping step:

| host UID                                         | intermediate UID |
| -                                                |                - |
| UID for the user starting Podman                 |                0 |
| 1st subordinate UID for the user starting Podman |                1 |
| 2nd subordinate UID for the user starting Podman |                2 |
| 3rd subordinate UID for the user starting Podman |                3 |
| nth subordinate UID for the user starting Podman |                n |

To be able to use intermediate UIDs greater than zero, the user needs to have
subordinate UIDs configured in _/etc/subuid_. See **subuid**(5).

The second mapping step is configured with **--uidmap**.

If for example _amount_ is **5** the second mapping step looks like:

|   intermediate UID   |    container UID    |
| -                    | -                   |
| _from_uid_           | _container_uid_     |
| _from_uid_ + 1       | _container_uid_ + 1 |
| _from_uid_ + 2       | _container_uid_ + 2 |
| _from_uid_ + 3       | _container_uid_ + 3 |
| _from_uid_ + 4       | _container_uid_ + 4 |

When running as rootless, Podman uses all the ranges configured in the _/etc/subuid_ file.

The current user ID is mapped to UID=0 in the rootless user namespace.
Every additional range is added sequentially afterward:

|   host                |rootless user namespace | length              |
| -                     | -                      | -                   |
| $UID                  | 0                      | 1                   |
| 1                     | $FIRST_RANGE_ID        | $FIRST_RANGE_LENGTH |
| 1+$FIRST_RANGE_LENGTH | $SECOND_RANGE_ID       | $SECOND_RANGE_LENGTH|

By default, providing either **--uidmap** or **--gidmap** replaces the
whole mapping. If only one of those two options is given, the other one is
copied by default.  If only one value of the two needs to be changed,
both values should be provided.

At times it may be desired that a specific host group needs to be mapped
that has already been subordinated within_/etc/subgid without specifying
the rest of the mapping when running as rootless. This can be done by
passing **--gidmap=+*container_gid*:*@host_gid*:1**. This uses the *+* sign
to extend the default mapping and not replace it. It also uses the
*@* sign to specify that the mapping refers to the host namespace, the parent
of the intermediate namespace. For instance, If the user belongs to the group
1002 and that group is subordinated to that user with
`usermod --add-subgids 1002-1002 $USER`, that group can be mapped into the
container with: **--gidmap=+10000:@1002:1**. If this mapping is combined with
the option, **--group-add=keep-groups**, the user in the container will belong
to group 10000, and files belonging to group 1002 in the host will appear as
being owned by group 10000 inside the container.

Even if a user does not have any subordinate UIDs in  _/etc/subuid_,
**--uidmap** can be used to map the normal UID of the user to a
container UID by running `podman <<subcommand>> --uidmap $container_uid:0:1 --user $container_uid ...`.

Note: the **--uidmap** flag cannot be called in conjunction with the **--pod** flag as a uidmap cannot be set on the container level when in a pod.

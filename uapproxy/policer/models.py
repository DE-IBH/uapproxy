from django.db import models
import uuid
import ipaddress
from packaging import version


def version_compare(parsed, comparator, model, fields):
    if parsed[fields[0]] is None:
        version_parsed = version.parse('')
    else:
        v = [parsed[fields[0]]]
        for field in fields[1:]:
            if parsed[field] is None or getattr(model, field) is None:
                break
            v.append(str(parsed[field]))
        version_parsed = version.parse(".".join(v))

    if comparator == Policy.COMP_LT:
        return version_parsed < model.version

    if comparator == Policy.COMP_LE:
        return version_parsed <= model.version

    if comparator == Policy.COMP_EQ:
        return version_parsed == model.version

    if comparator == Policy.COMP_NE:
        return version_parsed != model.version

    if comparator == Policy.COMP_GE:
        return version_parsed >= model.version

    if comparator == Policy.COMP_GT:
        return version_parsed > model.version

    assert("Unhandeld version comparator.")


class UserAgent(models.Model):
    uuid = models.UUIDField(
        primary_key=True, editable=False, default=uuid.uuid4)

    description = models.CharField(
        max_length=255, null=True, blank=True, help_text="description")

    family = models.CharField(max_length=48, help_text="ua's device family")
    major = models.PositiveIntegerField(null=True, blank=True)
    minor = models.PositiveIntegerField(null=True, blank=True)
    patch = models.PositiveIntegerField(null=True, blank=True)

    @property
    def version(self):
        if self.major is None:
            return version.parse('')

        v = [str(self.major)]
        if self.minor is not None:
            v.append(str(self.minor))
            if self.patch is not None:
                v.append(str(self.patch))

        return version.parse(".".join(v))

    def policy_check(self, ua, comparator):
        if ua['family']:
            if ua['family'] != self.family:
                return False

        return version_compare(ua, comparator, self, ['major', 'minor', 'patch'])

    def __str__(self):
        return " ".join(filter(None, [self.family, str(self.version)]))


class OperatingSystem(models.Model):
    uuid = models.UUIDField(
        primary_key=True, editable=False, default=uuid.uuid4)

    description = models.CharField(
        max_length=255, null=True, blank=True, help_text="description")

    family = models.CharField(max_length=48, help_text="ua's os family")
    major = models.PositiveIntegerField(null=True, blank=True)
    minor = models.PositiveIntegerField(null=True, blank=True)
    patch = models.PositiveIntegerField(null=True, blank=True)
    patch_minor = models.PositiveIntegerField(null=True, blank=True)

    @property
    def version(self):
        if self.major is None:
            return version.parse('')

        v = [str(self.major)]
        if self.minor is not None:
            v.append(str(self.minor))
            if self.patch is not None:
                v.append(str(self.patch))
                if self.patch_minor is not None:
                    v.append(str(self.patch_minor))

        return version.parse(".".join(v))

    def policy_check(self, uap, comparator):
        if uap['family']:
            if uap['family'] != self.family:
                return False

        return version_compare(uap, comparator, self, ['major', 'minor', 'patch', 'patch_minor'])

    def __str__(self):
        return " ".join(filter(None, [self.family, str(self.version)]))


class Device(models.Model):
    uuid = models.UUIDField(
        primary_key=True, editable=False, default=uuid.uuid4)

    description = models.CharField(
        max_length=255, null=True, blank=True, help_text="description")

    brand = models.CharField(max_length=48, help_text="ua's device brand")
    family = models.CharField(
        max_length=48, blank=True, default="", help_text="ua's device family")
    model = models.CharField(max_length=48, blank=True, default="",
                             help_text="ua's device model")

    def policy_check(self, uap, equal):
        matching = self.family == uap['family']

        if matching and self.brand:
            matching = self.brand == uap['brand']

        if matching and self.model:
            matching = self.model == uap['model']

        if equal:
            return matching
        else:
            return not matching

    def __str__(self):
        return "/".join(filter(None, [self.family, self.brand, self.model]))


class Prefix(models.Model):
    uuid = models.UUIDField(
        primary_key=True, editable=False, default=uuid.uuid4)

    description = models.CharField(
        max_length=255, null=True, blank=True, help_text="description")

    prefix = models.GenericIPAddressField(unpack_ipv4=True)
    length = models.PositiveSmallIntegerField()

    class Meta:
        verbose_name_plural = "prefixes"

    def policy_check(self, client_ip, inside):
        network = ipaddress.ip_network("{}/{}".format(self.prefix, self.length))
        if inside:        
            return client_ip in network
        else:
            return not client_ip in network

    def save(self, *args, **kwargs):
        # limit prefix length depending on ip family
        ip = ipaddress.ip_address(self.prefix)
        self.length = min(self.length, ip.max_prefixlen)

        # set prefix to network base address
        nw = ipaddress.ip_interface("{}/{}".format(self.prefix, self.length))
        self.prefix = str(nw.network.network_address)

        super().save(*args, **kwargs)  # Call the "real" save() method.

    def __str__(self):
        return str(ipaddress.ip_network("{}/{}".format(self.prefix, self.length)))


class Policy(models.Model):
    def get_free_priority():
        last_priority = Policy.objects.aggregate(models.Max('priority'))
        return (last_priority['priority__max'] or 0) + 10

    COMP_LT = 'LT'
    COMP_LE = 'LE'
    COMP_EQ = 'EQ'
    COMP_NE = 'NE'
    COMP_GE = 'GE'
    COMP_GT = 'GT'
    VERSION_CHOICES = [
        (COMP_LT, '<'),
        (COMP_LE, '≤'),
        (COMP_EQ, '='),
        (COMP_NE, '≠'),
        (COMP_GE, '≥'),
        (COMP_GT, '>'),
    ]

    DEV_BRAND = 'BR'
    DEV_FAMILY = 'FA'
    DEV_MODEL = 'MO'
    DEVICE_CHOICES = [
        (DEV_BRAND, 'Brand'),
        (DEV_FAMILY, 'Brand + Family'),
        (DEV_MODEL, 'Brand + Family + Model'),
    ]

    uuid = models.UUIDField(
        primary_key=True, editable=False, default=uuid.uuid4)

    priority = models.IntegerField(unique=True, default=get_free_priority)
    permit = models.BooleanField(default=True)

    ua = models.ForeignKey(UserAgent, null=True,
                           blank=True, on_delete=models.PROTECT)
    ua_comparator = models.CharField(
        max_length=2, default=COMP_LT, choices=VERSION_CHOICES)

    os = models.ForeignKey(OperatingSystem, null=True,
                           blank=True, on_delete=models.PROTECT)
    os_comparator = models.CharField(
        max_length=2, default=COMP_EQ, choices=VERSION_CHOICES)

    device = models.ForeignKey(
        Device, null=True, blank=True, on_delete=models.PROTECT)
    device_equal = models.BooleanField(
        default=True, help_text="If TRUE the device must match, if FALSE it must not match.")

    prefix = models.ForeignKey(
        Prefix, null=True, blank=True, on_delete=models.PROTECT)
    prefix_inside = models.BooleanField(
        default=True, help_text="If TRUE the client ip address must be inside the prefix, if FALSE it must not be inside.")

    matches = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['priority']
        verbose_name_plural = "policies"

    def policy_check(self, uap, client_ip):
        if self.ua is not None:
            if not self.ua.policy_check(uap['user_agent'], self.ua_comparator):
                return False

        if self.os is not None:
            if not self.os.policy_check(uap['os'], self.os_comparator):
                return False

        if self.device is not None:
            if not self.device.policy_check(uap['device'], self.device_equal):
                return False

        if self.prefix is not None:
            if not self.prefix.policy_check(client_ip, self.prefix_inside):
                return False

        return True

    def __str__(self):
        return "#{}".format(self.priority)

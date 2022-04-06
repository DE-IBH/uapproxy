from django.contrib import admin

# Register your models here.
import policer.models as models

@admin.register(models.UserAgent)
class UserAgentAdmin(admin.ModelAdmin):
    pass

@admin.register(models.OperatingSystem)
class OperatingSystemAdmin(admin.ModelAdmin):
    pass

@admin.register(models.Device)
class DeviceAdmin(admin.ModelAdmin):
    pass

@admin.register(models.Prefix)
class PrefixAdmin(admin.ModelAdmin):
    pass

@admin.register(models.Policy)
class PolicyAdmin(admin.ModelAdmin):
    exclude = ('matches',)
    list_display = ('priority', 'format_ua', 'format_os', 'format_device', 'format_prefix', 'permit', 'matches')
    
    def format_ua(self, policy):
        if policy.ua is None:
            return '-'

        return " {} ".format(policy.get_ua_comparator_display()).join(filter(None, [policy.ua.family, str(policy.ua.version)]))
    format_ua.short_description = "User-Agent"
    
    def format_os(self, policy):
        if policy.os is None:
            return '-'

        return " {} ".format(policy.get_os_comparator_display()).join(filter(None, [policy.os.family, str(policy.os.version)]))
    format_ua.short_description = "Operating System"
    
    def format_device(self, policy):
        if policy.device is None:
            return '-'

        if policy.device_equal:
            return "= {}".format(str(policy.device))
        else:
            return "≠ {}".format(str(policy.device))
    format_device.short_description = "Device"
    
    def format_prefix(self, policy):
        if policy.prefix is None:
            return '-'

        if policy.prefix_inside:
            return "⊆ {}".format(str(policy.prefix))
        else:
            return "⊈ {}".format(str(policy.prefix))
    format_prefix.short_description = "Prefix"

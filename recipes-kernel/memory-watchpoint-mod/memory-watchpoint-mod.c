#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/stacktrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roman Dykyi");
MODULE_DESCRIPTION("Memory Watchpoint Kernel Module");
MODULE_VERSION("1.0");

static unsigned long watch_addr = 0;
module_param(watch_addr, ulong, 0644);
MODULE_PARM_DESC(watch_addr, "Memory address to set hardware watchpoint");

static struct perf_event **hw_breakpoint_event;
static struct kobject *wp_kobj;

#define MAX_STACK_DEPTH 16
static void print_backtrace(void)
{
    unsigned long entries[MAX_STACK_DEPTH];
    int i, nr = stack_trace_save(entries, MAX_STACK_DEPTH, 1);

    pr_info("Watchpoint backtrace (depth %d):\n", nr);
    for (i = 0; i < nr; i++)
    {
        pr_info("[<%px>] %pS\n", (void *)entries[i], (void *)entries[i]);
    }
}

static void read_callback(struct perf_event *bp,
                                struct perf_sample_data *data,
                                struct pt_regs *regs)
{

    pr_info("Read trigger at address: 0x%lx\n", watch_addr);

    if (hw_breakpoint_event) {
        unregister_wide_hw_breakpoint(hw_breakpoint_event);
        hw_breakpoint_event = NULL;
        pr_info("Watchpoint automatically removed after trigger\n");
    }

}

static void write_callback(struct perf_event *bp,
                                struct perf_sample_data *data,
                                struct pt_regs *regs)
{

    pr_info("Write trigger at address: 0x%lx\n", watch_addr);

    if (hw_breakpoint_event) {
        unregister_wide_hw_breakpoint(hw_breakpoint_event);
        hw_breakpoint_event = NULL;
        pr_info("Watchpoint automatically removed after trigger\n");
    }

}

static int setup_watchpoint(void)
{
    struct perf_event_attr attr;

    if (!watch_addr) {
        pr_err("Invalid watchpoint address: 0x%lx\n", watch_addr);
        return -EINVAL;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = watch_addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_R;

    hw_breakpoint_event = register_wide_hw_breakpoint(&attr, read_callback, NULL);
    if (IS_ERR(hw_breakpoint_event)) {
        pr_err("Failed to register read hardware watchpoint: %ld\n", PTR_ERR(hw_breakpoint_event));
        hw_breakpoint_event = NULL;
        return PTR_ERR(hw_breakpoint_event);
    }

    attr.bp_addr = watch_addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_W;

    hw_breakpoint_event = register_wide_hw_breakpoint(&attr, write_callback, NULL);
    if (IS_ERR(hw_breakpoint_event)) {
        pr_err("Failed to register  write hardware watchpoint: %ld\n", PTR_ERR(hw_breakpoint_event));
        hw_breakpoint_event = NULL;
        return PTR_ERR(hw_breakpoint_event);
    }

    pr_info("Hardware watchpoint set at address: 0x%lx\n", watch_addr);
    return 0;
}

static void cleanup_watchpoint(void)
{
    if (hw_breakpoint_event) {
        unregister_wide_hw_breakpoint(hw_breakpoint_event);
        hw_breakpoint_event = NULL;
        pr_info("Watchpoint removed\n");
    }
}

static ssize_t addr_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "0x%lx\n", watch_addr);
}

static ssize_t addr_store(struct kobject *kobj, struct kobj_attribute *attr,
                          const char *buf, size_t count)
{
    unsigned long addr;
    int ret;

    ret = kstrtoul(buf, 0, &addr);
    if (ret) {
        pr_err("Invalid address format\n");
        return ret;
    }

    cleanup_watchpoint();

    watch_addr = addr;
    ret = setup_watchpoint();
    if (ret) {
        pr_err("Failed to set new watchpoint\n");
        return ret;
    }

    return count;
}

static struct kobj_attribute wp_addr_attr = __ATTR(watch_addr, 0664, addr_show, addr_store);

static int __init wp_init(void)
{
    int ret;

    wp_kobj = kobject_create_and_add("wp_module", kernel_kobj);
    if (!wp_kobj) {
        return -ENOMEM;
    }

    ret = sysfs_create_file(wp_kobj, &wp_addr_attr.attr);
    if (ret) {
        kobject_put(wp_kobj);
        return ret;
    }

    ret = setup_watchpoint();
    if (ret) {
        kobject_put(wp_kobj);
        return ret;
    }

    pr_info("Watchpoint module loaded\n");
    return 0;
}

static void __exit wp_exit(void)
{
    cleanup_watchpoint();

    if (wp_kobj)
    {
        kobject_put(wp_kobj);
    }

    pr_info("Watchpoint module unloaded\n");
}

module_init(wp_init);
module_exit(wp_exit);
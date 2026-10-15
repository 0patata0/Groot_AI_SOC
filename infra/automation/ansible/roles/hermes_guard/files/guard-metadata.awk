# Only recreate bounded, allowlisted metadata. Never print an input log line.
# Counts are observations, not total responses or a unique-message error rate.
/^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}([,.][0-9]+)?([+][0-9:]+|Z)? INFO capstone_korean_output_guard: korean_output_guard verdict=(oversize|requested_foreign|retained|filtered) chars=[0-9]{1,10}$/ {
    match($0, /korean_output_guard verdict=(oversize|requested_foreign|retained|filtered) chars=[0-9]{1,10}$/)
    fragment = substr($0, RSTART, RLENGTH)
    count = split(fragment, fields, /[[:space:]]+/)
    if (count >= 3) {
        print "korean_output_guard " fields[2] " " fields[3]
        fflush()
    }
}

use pingora_load_balancing::{selection::BackendSelection, LoadBalancer};

pub struct LB<BS: BackendSelection> {
    // LB
    pub load_balancer: LoadBalancer<BS>,
    // hash_on
    // health_check
    // retry
    // host rewrite
}

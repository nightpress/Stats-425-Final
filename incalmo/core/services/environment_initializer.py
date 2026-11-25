from config.attacker_config import AttackerConfig, Environment
from incalmo.core.models.network import Network, Subnet


class EnvironmentInitializer:
    def __init__(self, config: AttackerConfig):
        self.attacker_config = config

    def get_initial_environment_state(self):
        if (
            self.attacker_config.environment == Environment.EQUIFAX_LARGE.value
            or self.attacker_config.environment == Environment.EQUIFAX_MEDIUM.value
            or self.attacker_config.environment == Environment.EQUIFAX_SMALL.value
        ):
            # In Equifax, attacker knows external subnet
            network = Network([Subnet("192.168.200.0/24")])
            return network
        elif self.attacker_config.environment == Environment.ICS.value:
            # In ICS, attacker has no initial network knowledge
            return Network([])
        elif self.attacker_config.environment == Environment.RING.value:
            # In ring, attacker has no initial network knowledge
            return Network([])
        elif self.attacker_config.environment == Environment.ENTERPRISE_A.value:
            return Network(
                [
                    Subnet("192.168.200.0/24"),
                    Subnet("192.168.201.0/24"),
                    Subnet("192.168.203.0/24"),
                ]
            )
        elif self.attacker_config.environment == Environment.ENTERPRISE_B.value:
            return Network(
                [
                    Subnet("192.168.200.0/24"),
                    Subnet("192.168.201.0/24"),
                    Subnet("192.168.203.0/24"),
                    Subnet("192.168.204.0/24"),
                ]
            )
        elif self.attacker_config.environment == Environment.MHBENCH_SUDOBARON_TEST.value:
            # Matches MHBench/environments/instrumented/sudobaron_test_instrumented.json:
            # target_subnet (host0) <-> attacker_subnet (attacker), merged onto one
            # Docker bridge (docker/mhbench/sudobaron_test/docker-compose.yml) since
            # that spec connects them directly with no intermediate host. Shifted to
            # 192.168.210.0/24 (off the main range's 199-201 block) so this topology
            # can run alongside the main Equifax range without a subnet collision.
            # defender_subnet is unreachable per that spec and is omitted here.
            return Network([Subnet("192.168.210.0/24")])
        elif self.attacker_config.environment == Environment.MHBENCH_CHAIN_2HOSTS.value:
            # Matches MHBench/environments/instrumented/chain_2hosts_instrumented.json:
            # ring_subnet (host0, host1) <-> attacker_subnet (attacker), merged onto
            # one Docker bridge (docker/mhbench/chain_2hosts/docker-compose.yml) since
            # that spec connects them directly with no intermediate host. Shifted to
            # 192.168.211.0/24 for the same collision-avoidance reason as above.
            # defender_subnet is unreachable per that spec and is omitted here.
            return Network([Subnet("192.168.211.0/24")])
        elif self.attacker_config.environment == Environment.MHBENCH_NETCAT_TEST.value:
            # docker/mhbench/netcat_test/docker-compose.yml: attacker + host0
            # on one shared bridge (no MHBench topology isolates netcat_shell
            # alone, so this is built at the same minimal scale as
            # sudobaron_test rather than drawn from one specific spec file).
            return Network([Subnet("192.168.212.0/24")])
        return Network([Subnet("192.168.200.0/24")])

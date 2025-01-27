package kan9hee.nolaejui_auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cloud.client.discovery.EnableDiscoveryClient

@SpringBootApplication
@EnableDiscoveryClient
class NolaejuiAuthApplication

fun main(args: Array<String>) {
	runApplication<NolaejuiAuthApplication>(*args)
}

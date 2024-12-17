package kan9hee.nolaejui_auth.dao

import kan9hee.nolaejui_auth.entity.BlacklistToken
import org.springframework.data.repository.CrudRepository

interface BlacklistTokenRepository:CrudRepository<BlacklistToken,String> {
}
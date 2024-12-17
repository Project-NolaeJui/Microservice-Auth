package kan9hee.nolaejui_auth.dao

import kan9hee.nolaejui_auth.entity.RefreshToken
import org.springframework.data.repository.CrudRepository

interface RefreshTokenRepository:CrudRepository<RefreshToken,String> {
}
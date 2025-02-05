package kan9hee.nolaejui_auth.service

import org.springframework.stereotype.Service
import MusicListServerGrpcKt
import net.devh.boot.grpc.client.inject.GrpcClient

@Service
class ExternalService(@GrpcClient("nolaejui-playlist")
                      private val playlistStub:MusicListServerGrpcKt.MusicListServerCoroutineStub) {

    suspend fun createAndDeletePlaylistForUser(userName:String,isCreate:Boolean){
        val request = Auth.UserCD.newBuilder()
            .setUserName(userName)
            .setIsCreate(isCreate)
            .build()

        val response = playlistStub.createAndDeletePlaylistForUser(request)
        if(!response.isSuccess)
            throw RuntimeException(response.resultMessage)
    }
}
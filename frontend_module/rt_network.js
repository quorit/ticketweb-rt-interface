

class NetworkError extends Error {
   constructor(message) {
      super(message);
      this.name="RT_NetworkError"
   }
}

class HTTPResponseError extends NetworkError {
   //this error is for any http response error that is not failed session authentication
   constructor(status_code,message){
      super(message);
      this.status_code = status_code;
      this.name="RT_HTTPResponseError"
   }
}




class ConnectionError extends NetworkError {
   //this is for when a fetch fails and we don't even get a response
   constructor(message){
      super(message);
      this.name="RT_ConnectionError"
   }
}



function test_ok(response) {
    return new Promise ((resolve,reject) => {
       if (response.ok){
          resolve (response);
       }else{
         var str = "Server returned " + response.status + " : " + response.statusText;
         if(response.status){
            reject(new HTTPResponseError(response.status,str));
         }else{
            reject(new ConnectionError("No response status. Probably no connection."));
         }
       }
    });
}


function extended_fetch(url,opts){
   return fetch(url,opts).then(response => response,err=> new ConnectionError(err.message));
}

function fetch_init_data(shared_data_path){
   const init_data_url = window.location.origin + shared_data_path + "init_data.json";

   return extended_fetch(
      init_data_url, 
      {   
         method: "GET",
         mode: "cors"
      })
      .then(test_ok)
      .then(response => response.json());
   

}







function get_user_data(app_token,app_server_path){
   const api_root = window.location.origin + app_server_path;
   const url = api_root + "user-data";
   return extended_fetch(
      url, 
      {   
         method: "GET",
         mode: "cors",
         headers: new Headers({
            "Authorization": "Bearer " + app_token,
         }),
      })
      .then(test_ok)
      .then(response => response.json());
}

function submit_data_internal(submission_data,form_type,app_token,app_server_path){
   const api_root = window.location.origin + app_server_path;
   const api_url = api_root + "submit-ticket/" + form_type;
   return extended_fetch(
      api_url, 
      {   
         method: "POST",
         headers: new Headers({
           "Authorization": "Bearer " + app_token
         }),
         mode: "cors",
         body: submission_data
      }
   )
   .then(test_ok)
   .then(response => response.json());


}

function submit_data(json,
                     attachments,form_type,app_token,app_server_path){
   const formData = new FormData();
   formData.append("json",
                  new Blob([
                             JSON.stringify(json)
                           ], 
                  {
                     type: "application/json"
                  })
                  );
   for (const file of attachments){
      formData.append("attachment",file);
   }
   return submit_data_internal(formData,
                               form_type,
                               app_token,
                               app_server_path);


}





module.exports = {submit_data, fetch_init_data,
        ConnectionError,HTTPResponseError,NetworkError,get_user_data
      
      }

function Logger(){
    this.enableLocal = true;
}

Logger.prototype.log = function(strMessage, strSource){
    if(this.enableLocal){
        console.log(strSource + ': ' + strMessage);
    }
}

module.exports = new Logger();
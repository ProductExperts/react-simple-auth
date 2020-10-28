export default function to<T>(promise: Promise<T>) {
    return promise.then(data => {
        return [null, data];
    })
        .catch(err => {
            return [err]
        });
}